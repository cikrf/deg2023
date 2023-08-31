// @ts-ignore
import { GostEngine as gostEngine } from '@wavesenterprise/crypto-gost-js/dist/CryptoGost'
import * as EC from 'elliptic'
import * as hash from 'hash.js'
import { CurvePoint, KeyPair } from '../types'

const gostHashParams = {
  name: 'GOST R 34.11',
  version: 2012,
  mode: 'HASH',
  length: 256,
  procreator: 'CP',
  keySize: 32,
}

const gostSignParams = {
  name: 'GOST R 34.10',
  version: 2012,
  mode: 'SIGN',
  length: 256,
  procreator: 'CP',
  keySize: 32,
  namedCurve: 'S-256-A',
  hash: gostHashParams,
  id: 'id-tc26-gost3410-12-256',
}

export const gostVerify = (publicKey: Buffer, signature: Buffer, data: Buffer) => {
  const GostSign = gostEngine.getGostSign(gostSignParams)
  return GostSign.verify(publicKey, signature, data)
}

export const gostId = (data: Buffer | string): Buffer => {
  if (typeof data === 'string') {
    data = Buffer.from(data)
  }
  const GostDigest = gostEngine.getGostDigest(gostHashParams)
  return new Buffer(GostDigest.digest(data))
}

export const P = 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd97'
export const Q = 'ffffffffffffffffffffffffffffffff6c611070995ad10045841b09b761b893'
export const B = '00000000000000000000000000000000000000000000000000000000000000a6'
export const A = 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd94'

const x = '0000000000000000000000000000000000000000000000000000000000000001'
const y = '8d91e471e0989cda27df505a453f2b7635294f2ddf23e3b122acc99c9e9f1e14'

export const BASE_COMPRESSED = '020000000000000000000000000000000000000000000000000000000000000001'
export const BASE = `04${x}${y}`

const paramSetA = new EC.curves.PresetCurve({
  type: 'short',
  prime: null,
  p: P,
  a: A,
  b: B,
  n: Q,
  hash: hash.sha256,
  gRed: false,
  g: [
    x,
    y,
  ],
})

export const streebog256 = (data: Buffer) => {
  const streebog = gostEngine.getGostDigest(

  )
  return Buffer.from(streebog.digest(data))
}

export const curve = new EC.ec(paramSetA)
export const createPoint = (point: Buffer | string): CurvePoint => {
  if (typeof point === 'string') {
    return curve.keyFromPublic(point, 'hex').getPublic()
  } else if (Buffer.isBuffer(point)) {
    return curve.keyFromPublic(point.toString('hex'), 'hex').getPublic()
  } else {
    throw new Error('Unknown point format')
  }
}

export const generateKeyPair = (): KeyPair => {
  const keypair = curve.genKeyPair()
  return {
    privateKey: keypair.getPrivate().toBuffer('be'),
    publicKey: Buffer.from(keypair.getPublic().encode('array', true)),
  }
}

export const mapPointToLE = (p: CurvePoint, inf = false) => {
  const bytes = p.encode('array', false)
  const isInfinity = inf ? [(p.isInfinity() ? 0 : 1)] : []
  const res = Buffer.from([
    ...isInfinity,
    ...bytes.slice(1, 33).reverse(),
    ...bytes.slice(33, 65).reverse(),
  ])
  return res
}

export const mapPointToBE = (data: Buffer) => {
  let coords: Buffer
  if (data.length === 64) {
    coords = data
  } else if (data.length === 65) {
    const isInfinity = data[0] === 0
    if (isInfinity) {
      throw new Error('Point at Infinity in decrypted part')
    }
    coords = data.slice(1)
  } else {
    throw new Error('Wrong point format')
  }

  const X_BE = Buffer.from(coords).slice(0, 32).reverse().toString('hex')
  const Y_BE = Buffer.from(coords).slice(32, 64).reverse().toString('hex')
  const hex = `04${X_BE}${Y_BE}`

  const P = createPoint(Buffer.from(hex, 'hex'))
  return Buffer.from(P.encodeCompressed('hex'), 'hex')
}
