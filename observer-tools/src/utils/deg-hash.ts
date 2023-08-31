import { streebog256 } from './gost-utils'
import { xor } from './byte-utils'

const ARRAY_32_BYTES = 32
const ARRAY_64_BYTES = 64

export class DEGHash {
  static DST = Buffer.from('BlindSign-TeZhu-V00-H2F:id-tc26-gost-3410-2012-256-paramSetB_Streebog-256_XMD_ROP', 'utf-8')

  static L = 48
  static LL = 2
  static MASK = 0xFF
  static TMP_B0 = DEGHash.L & DEGHash.MASK
  static TMP_B1 = DEGHash.L >>> 8
  static ZERO = 0

  static hash(msg: Buffer) {
    const bb = Buffer.from([
      ...Array(ARRAY_64_BYTES).fill(0),
      ...msg,
      DEGHash.TMP_B1,
      DEGHash.TMP_B0,
      DEGHash.ZERO,
      ...DEGHash.DST,
    ])

    const firstRoundHash = streebog256(bb)
    let nextRoundHash = Buffer.alloc(ARRAY_32_BYTES).fill(0)
    let resultBuffer = Buffer.alloc(0)

    for (let i = 1; i <= DEGHash.LL; i++) {
      const xored = xor(nextRoundHash, firstRoundHash)
      const internalBb = Buffer.from([
        ...xored,
        i,
        ...DEGHash.DST,
      ])

      nextRoundHash = streebog256(internalBb)

      resultBuffer = Buffer.from([
        ...resultBuffer,
        ...nextRoundHash,
      ])
    }

    const result = Buffer.alloc(DEGHash.L)
    resultBuffer.copy(result, 0, 0, DEGHash.L)
    return result
  }
}
