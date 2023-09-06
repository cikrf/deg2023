import { ABBytes, Decryption } from '../types'
import { createPoint, mapPointToLE } from './gost-utils'
import * as ref from 'ref-napi'
import * as path from 'path'
import * as os from 'os'
import * as ffi from 'ffi-napi'

const ArrayType = require('ref-array-di')(ref)
const StructType = require('ref-struct-di')(ref)

export const szOID_tc26_gost_3410_12_256_paramSetB = '1.2.643.7.1.2.1.1.2'
export const ENCRYPTION_PUBLIC_CALCMETHOD_1 = 1

export enum HSM_TYPE {
  USER = 1,
  SUM = 2,
  DECRYPTED_PART = 3,
  RESULT = 4,
}

const byteArr = ArrayType(ref.types.byte)
const byteArrPtr = ref.refType(byteArr)

export const CryptDataBlobType = StructType({
  cbData: ref.types.int,
  pbData: byteArrPtr,
})

export const CryptDataBlobPtr = ref.refType(CryptDataBlobType)

export const CBD = (data: Buffer) => {
  const struct = new CryptDataBlobType()
  const pbData = Buffer.alloc(data.length)
  data.copy(pbData, 0, 0, data.length)
  pbData.type = byteArrPtr

  const cbData = ref.alloc(ref.types.uint32)
  cbData.writeInt32LE(data.length)
  cbData.type = ref.types.int

  struct.cbData = data.length
  struct.pbData = pbData
  return struct
}

export const HSM_VERSION = 0
export const HSM_CURVE_ID = 1
export const HSM_RESERVED = 0

const LIBRARY_DIR: { [key: string]: string } = {
  'darwin': './lib',
  'linux': './lib',
}

const LIBRARY_NAME = 'libcpblindsig'
const LIBRARY_PATH = path.resolve(LIBRARY_DIR[os.platform()], LIBRARY_NAME)

const lib = ffi.Library(LIBRARY_PATH, {
  VerifyDecryptedPart: [
    ref.types.bool,
    [
      CryptDataBlobPtr,
      CryptDataBlobPtr,
      CryptDataBlobPtr,
      CryptDataBlobPtr,
    ],
  ],
  VerifyBlindSignature: [ref.types.bool, [CryptDataBlobPtr, CryptDataBlobPtr, CryptDataBlobPtr]],
  GetLastError: [ref.types.uint32, []],
})

export const getHeader = (type: HSM_TYPE, length: number) => {
  const dwFields = Buffer.alloc(4)
  dwFields.writeInt32LE(length, 0)
  return Buffer.from([
    type,
    HSM_VERSION,
    HSM_CURVE_ID,
    HSM_RESERVED,
    ...dwFields,
  ])
}

export const recoverDecryption = (data: Decryption[]) => {
  const num = data.length
  const header = getHeader(HSM_TYPE.DECRYPTED_PART, num)
  const content = data.map(({ P, w, U1, U2 }) => {
    return Buffer.from([
      ...mapPointToLE(createPoint(P), true),
      ...Buffer.from(w, 'hex').reverse(),
      ...mapPointToLE(createPoint(U1), true),
      ...mapPointToLE(createPoint(U2), true),
    ])
  })

  return Buffer.from([
    ...header,
    ...Buffer.concat(content),
  ])
}

export const mapSums = (data: ABBytes[]) => {
  const num = data.length
  const header = getHeader(HSM_TYPE.SUM, num)
  const content = data.map(({ A, B }) => {
    return Buffer.from([
      ...mapPointToLE(createPoint(A), true),
      ...mapPointToLE(createPoint(B), true),
    ])
  })
  return Buffer.from([
    ...header,
    ...Buffer.concat(content),
  ])
}

export const validateDecryptionCryptoPro = (ctx: string, sums: ABBytes[], publicKey: string, decryption: Decryption[]) => {
  return lib.VerifyDecryptedPart(
    CBD(mapSums(sums)).ref(),
    CBD(mapPointToLE(createPoint(publicKey))).ref(),
    CBD(Buffer.from(ctx)).ref(),
    CBD(recoverDecryption(decryption)).ref(),
  )
}

export const validateBlindSignature = (publicKey: Buffer, signature: Buffer, message: Buffer) => {
  return lib.VerifyBlindSignature(
    CBD(publicKey).ref(),
    CBD(message).ref(),
    CBD(signature).ref(),
  )
}

