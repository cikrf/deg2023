import * as Farm from 'worker-farm'
import { Methods } from './worker'
import { ContractState, Decryption, DLPResult, SumAB, Tx, ValidationResult } from '../types'
import { chunk, isEqual } from 'lodash'
import { createPoint } from '../utils/gost-utils'
import { fromHex, hashPoints } from '../utils/utils'
import * as BN from 'bn.js'
import { logVerbose } from '../utils/log-utils'
import * as os from 'os'

const maxConcurrentCallsPerWorker = 3
export const threadsNum = os.cpus().length
export const chunkSize = threadsNum * maxConcurrentCallsPerWorker

export const farm = Farm({
  workerOptions: {
    serialization: 'advanced',
  },
  autoStart: true,
  maxConcurrentCallsPerWorker: 3,
  maxConcurrentWorkers: threadsNum,
  maxRetries: 1,
}, require.resolve('./worker'), [
  Methods.addVotesChunk,
  Methods.validateBulletin,
  Methods.solveDLP,
  Methods.verifyDLEq,
  Methods.validateBlindSignature,
  Methods.encryptedSums,
  Methods.validateTxSignature,
  Methods.validateDecryptionZKP,
])

export const terminateWorkers = () => {
  logVerbose('Завершение работы')
  Farm.end(farm)
}

export const addVotesChunk = async (ABs: SumAB[], dimension: number[]): Promise<SumAB> => {
  const batches = chunk(ABs, Math.ceil(ABs.length / threadsNum))
  const wrapped = (ABs: SumAB[], dimension: number[]): Promise<SumAB> =>
    new Promise((resolve, reject) => {
      farm[Methods.addVotesChunk](ABs, dimension, (result: Error | SumAB) => {
        if (result instanceof Error) {
          reject(result)
        } else {
          resolve(result)
        }
      })
    })

  const promises = batches.map((chunk) => wrapped(chunk, dimension))
  const result = await Promise.all(promises)
  return wrapped(result, dimension)
}

export const validateBlindSignature = async (contractState: ContractState, tx: Tx) => {
  return new Promise((resolve, reject) => {
    farm[Methods.validateBlindSignature](contractState, tx, (result: Error | boolean) => {
      if (result instanceof Error) {
        reject(result)
      } else {
        resolve(result)
      }
    })
  })
}

export const validateTxSignature = async (tx: Tx): Promise<boolean> => {
  return new Promise((resolve, reject) => {
    farm[Methods.validateTxSignature](tx, (result: Error | boolean) => {
      if (result instanceof Error) {
        console.log('123123123123123123')
        reject(result)
      } else {
        resolve(result)
      }
    })
  })
}

export const validateDLEq = async (
  w: Buffer,
  U1: Buffer,
  U2: Buffer,
  G1: Buffer,
  Y1: Buffer,
  G2: Buffer,
  Y2: Buffer,
): Promise<boolean> => {
  return new Promise((resolve, reject) => {
    farm[Methods.verifyDLEq]({ w, U1, U2, G1, Y1, G2, Y2 }, (result: Error | boolean) => {
      if (result instanceof Error) {
        reject(result)
      } else {
        resolve(result)
      }
    })
  })
}

export const validateDecryption = async (ctx: string, sums: SumAB, dimension: number[], publicKey: Buffer, decryption: Decryption[][]): Promise<void> => {
  const promises = dimension.map(async (_options, qIdx) => {
    return new Promise((resolve, reject) => {
      farm[Methods.validateDecryptionZKP](ctx, sums[qIdx], publicKey, decryption[qIdx], (result: Error | boolean) => {
        if (result instanceof Error) {
          reject(result)
        } else {
          resolve(result)
        }
      })
    })
  })
  const results = await Promise.all(promises)
  if (!results.every(Boolean)) {
    throw new Error('Decryption is not valid')
  }
}

export const calculateResults = async (
  sums: SumAB,
  dimension: number[],
  n: number,
  master: any,
  commission: any,
): Promise<number[][]> => {

  const p1 = fromHex(master.publicKey)
  const p2 = fromHex(commission.publicKey)
  const h1 = hashPoints([p1, p2])
  const h2 = hashPoints([p2, p1])

  const encryptedSums = dimension.map((options, qIdx) => {
    return Array(options).fill(0).map((_, oIdx) => {
      const P1 = createPoint(master.decryption[qIdx][oIdx].P).mul(new BN(h1))
      const P2 = createPoint(commission.decryption[qIdx][oIdx].P).mul(new BN(h2))

      const C = P1.add(P2)

      if (C.eq(createPoint(sums[qIdx][oIdx].B))) {
        return 0
      } else {
        return Buffer.from(createPoint(sums[qIdx][oIdx].B)
          .add(C.neg())
          .encodeCompressed('array'),
        )
      }
    })
  })

  const Qs = [...encryptedSums]
    .flatMap((Q) => Q)
    .filter((Q1, idx, self) => {
      return idx === self.findIndex((Q2) => isEqual(Q1, Q2))
    })
    .filter((Q) => Q !== 0)

  const decryptedQs = await new Promise((resolve, reject) => {
    farm[Methods.solveDLP](Qs, n, (result: Error | DLPResult) => {
      if (result instanceof Error) {
        reject(result)
      } else {
        resolve(result)
      }
    })
  })

  return encryptedSums.map((options: any[]) => {
    return options.map((sum) => {
      if (sum === 0) {
        return 0
      } else {
        const key = Buffer.from(sum).toString('hex')
        return (decryptedQs as any).find((Q: { key: string }) => {
          return key === Q.key
        }).sum
      }
    })
  })
}

export const validateBulletin = async (vote: Tx, mainKey: string, dimension: number[][]) => {
  const binary = Buffer.from(vote.params.vote, 'base64')
  const result = await new Promise<ValidationResult>((resolve, reject) => {
    farm[Methods.validateBulletin](binary, mainKey, dimension, (result: Error | ValidationResult) => {
      if (result instanceof Error) {
        reject(result)
      } else {
        resolve(result)
      }
    })
  })
  return {
    txId: vote.txId,
    valid: result.valid,
  }

}

process.on('beforeExit', terminateWorkers)

process.on('SIGINT', () => {
  terminateWorkers()
  process.exit(0)
})
