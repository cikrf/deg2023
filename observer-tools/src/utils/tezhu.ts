import { BASE, createPoint, Q as curveQ } from './gost-utils'
import * as BN from 'bn.js'
import { CurvePoint } from '../types'
import { DEGHash } from './deg-hash'

export class PublicKey {
  Q: CurvePoint
  Z: CurvePoint

  constructor(publicKey: Buffer) {
    const Q_LE = publicKey.slice(2, 66)
    const Z_LE = publicKey.slice(66, 130)

    const Q_BE = Buffer.from([0x4, ...Q_LE.slice(0, 32).reverse(), ...Q_LE.slice(32, 64).reverse()]).toString('hex')
    const Z_BE = Buffer.from([0x4, ...Z_LE.slice(0, 32).reverse(), ...Z_LE.slice(32, 64).reverse()]).toString('hex')

    this.Q = createPoint(Q_BE)
    this.Z = createPoint(Z_BE)
  }
}

export class Signature {
  c: BN
  s: BN
  y: BN
  t: BN

  constructor(signature: Buffer) {
    const c = signature.slice(0, 32).reverse()
    const s = signature.slice(32, 64).reverse()
    const y = signature.slice(64, 96).reverse()
    const t = signature.slice(96, 128).reverse()

    this.c = new BN(c)
    this.s = new BN(s)
    this.y = new BN(y)
    this.t = new BN(t)
  }
}

export const verify = (publicKey: Buffer, signature: Buffer, message: Buffer) => {
  const G = createPoint(BASE)
  const { Q, Z } = new PublicKey(publicKey)
  const { s, y, t, c } = new Signature(signature)

  const C = G.mul(t).add(Z.mul(y))
  const A = G.mul(s).add(Q.mul(y).mul(c).neg())

  const A_BE = A.encode('array', false).slice(1)
  const A_LE = [...A_BE.slice(0, 32).reverse(), ...A_BE.slice(32, 64).reverse()]
  const C_BE = C.encode('array', false).slice(1)
  const C_LE = [...C_BE.slice(0, 32).reverse(), ...C_BE.slice(32, 64).reverse()]
  const m = Buffer.from([...A_LE, ...C_LE, ...message])

  const hash = DEGHash.hash(m)

  const cp = new BN(hash).umod(new BN(curveQ, 'hex'))

  return c.eq(cp)
}
