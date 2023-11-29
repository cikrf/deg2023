import { resolve } from 'path'
import * as readline from 'readline'
import * as fs from 'fs'
import { parseLine } from './utils/parse-line'
import { ContractState, STATE_TX_OPERATIONS, SumAB, Tx, ValidationConfig, VotingOperation } from './types'
import { log, logError, logVerbose } from './utils/log-utils'
import { getFiles } from './utils/get-files'
import { chunk, isEqual } from 'lodash'
import { addVotesChunk, calculateResults, chunkSize, validateBlindSignature, validateBulletin, validateDecryption, validateTxSignature } from './worker'
import { getContractState } from './utils/get-contract-state'
import { decode } from '@wavesenterprise/rtk-encrypt/dist'
import { getABs } from './utils/get-abs'

export const validate = async (contractId: string, dir: string, config: ValidationConfig) => {
  const files = await getFiles(resolve(dir, `*.csv`))

  if (files.length === 0) {
    logError('Файлы с транзакциями указанного голосования не найдены')
    return
  }

  const buffer: Tx[] = []
  log('Проверка подписей транзакций и учет роллбеков...')
  for (const filename of files) {
    const fileStream = fs.createReadStream(filename, {
      start: 0,
    })
    const rl = readline.createInterface({
      input: fileStream,
      crlfDelay: Infinity,
    })
    for await (const line of rl) {
      const tx = parseLine(line, contractId)
      if (tx.rollback) {
        const idx = buffer.findIndex(({ txId }) => tx.txId === txId)
        buffer.splice(idx, 1)
        logVerbose(`${tx.txId.padStart(44, ' ')}: Транзакция удалена (роллбек)`)
      } else {
        buffer.push(tx)
      }
    }
    rl.close()
    fileStream.close()
  }

  await Promise.all(chunk(buffer, chunkSize).map(async (txs) => {
    if (config.txSig) {
      await Promise.all(txs.map(async (tx) => {
        try {
          tx.valid = await validateTxSignature(tx)
        } catch (e) {
          logError(e)
          tx.valid = false
        }
        if (tx.valid) {
          logVerbose(`${tx.txId.padStart(44, ' ')}: Подпись транзакции корректна`)
        } else {
          logError(`${tx.txId.padStart(44, ' ')}: Неверная подпись транзакции`)
        }
      }))
    } else {
      txs.map((tx) => tx.valid = true)
    }
  }))

  // Восстанавливаем стейт контракта
  const contractState = getContractState(buffer.filter((tx) => tx.valid && STATE_TX_OPERATIONS.includes(tx.operation)))

  if (!contractState.MAIN_KEY) {
    logError('Ошибка валидации голосования: не найден главный ключ')
  }

  if (!contractState.VOTING_BASE) {
    logError('Ошибка валидации голосования: не найдена конфигурация')
  }

  const mainKey = contractState.MAIN_KEY
  const dimension = contractState.VOTING_BASE.dimension

  log('Проверка на переголосования...')
  const voted: Set<string> = new Set()
  const unique = buffer
    .filter((tx) => tx.valid)
    .filter((tx) => tx.operation === VotingOperation.vote)
    .filter((tx) => !voted.has(tx.senderPublicKey) ? voted.add(tx.senderPublicKey) : false)

  const validVotes = (await Promise.all(chunk(unique, chunkSize).map(async (txs) => {
    const validChunkVotes = await Promise.all(txs.filter(async (tx) => {
      if (config.blindSig) {
        if (!await validateBlindSignature(contractState, tx)) {
          logError(`${tx.txId.padStart(44, ' ')}: Слепая подпись не прошла проверку`)
          return false
        } else {
          logVerbose(`${tx.txId.padStart(44, ' ')}: Слепая подпись корректна`)
        }
      }

      if (config.zkp) {
        const res = await validateBulletin(tx, mainKey, dimension)
        if (!res.valid) {
          logError(`${res.txId.padStart(44, ' ')}: Некорректный ZKP`)
          return false
        } else {
          logVerbose(`${res.txId.padStart(44, ' ')}: Проверка ZKP успешна`)
        }
      }
      return true
    }))

    return validChunkVotes
      .map((tx) => Buffer.from(tx.params.vote, 'base64'))
      .map((b) => decode(b))
      .map((b) => getABs(b))

  }))).flat()

  const totalVotes = validVotes.length
  while (validVotes.length > 1) {
    const sumChunk = validVotes.splice(0, chunkSize)
    const sum = await addVotesChunk(sumChunk, dimension.map(((d: any) => d[2])))
    validVotes.push(sum)
  }
  if (validVotes.length) {
    await checkSum(config, validVotes[0], contractState, totalVotes)
  }
}

async function checkSum(config: ValidationConfig, sumABs: SumAB, contractState: ContractState, validNum: number) {
  const dimension = contractState.VOTING_BASE.dimension.map((o: any[]) => o[2])
  log('Зашифрованная сумма подсчитана.')

  let masterPublicKey, masterDecryption, masterCtx = ''
  let commissionDecryption, commissionPublicKey

  Object.entries(contractState).map(([key, value]) => {
    if (key === 'DKG_KEY' && typeof value === 'string') {
      masterPublicKey = value
    } else if (key === 'COMMISSION_KEY' && typeof value === 'string') {
      commissionPublicKey = value
    } else if (key.indexOf('DECRYPTION_') > -1 && typeof value === 'string') {
      masterDecryption = JSON.parse(value)
    } else if (key === 'COMMISSION_DECRYPTION' && typeof value === 'string') {
      commissionDecryption = JSON.parse(value)
    } else if (key === 'VOTING_BASE') {
      masterCtx = value.pollId
    }
  })

  log(`Количество валидных бюллетеней: ${validNum}`)
  if (config.debug) {
    const result = contractState.RESULTS.map((question: number[]) => question.reduce((acc, option) => acc + option), 0)
    log(`Сумма из результатов ${JSON.stringify(result)}`)
  }

  if (masterDecryption && commissionDecryption && masterPublicKey && commissionPublicKey) {
    try {
      await validateDecryption(masterCtx, sumABs, dimension, masterPublicKey, masterDecryption)
      log('Расшифровка сервера корректна.')
    } catch (e) {
      logError('Расшифровка сервера некорректна.')
    }
    try {
      await validateDecryption(masterCtx, sumABs, dimension, commissionPublicKey, commissionDecryption)
      log('Расшифровка комиссии корректна.')
    } catch (e) {
      logError('Расшифровка комиссии некорректна.')
    }
  } else {
    throw new Error('Не хватает данных для проверки расшифровок.')
  }
  log(`\nПодсчет результата...`)

  const calculated = await calculateResults(
    sumABs,
    dimension,
    validNum,
    {
      publicKey: masterPublicKey,
      decryption: masterDecryption,
    },
    {
      publicKey: commissionPublicKey,
      decryption: commissionDecryption,
    },
  )

  log(`Результат из блокчейна: ${JSON.stringify(contractState.RESULTS)}`)
  log(`Подсчитанный результат: ${JSON.stringify(calculated)}`)
  if (isEqual(calculated, contractState.RESULTS)) {
    log('Результаты равны.')
  } else {
    logError('Результаты не совпадают')
  }
}
