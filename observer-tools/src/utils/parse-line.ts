import { fieldsEnum, Tx, VotingOperation } from '../types'

const mapDataEntry = (param: any) => {
  let val
  if (param.stringValue && param.stringValue !== '') {
    val = param.stringValue
  } else if (param.binaryValue) {
    val = param.binaryValue
  } else if (param.intValue) {
    val = +param.intValue
  } else if (param.boolValue) {
    val = Boolean(param.boolValue)
  } else {
    val = ''
  }
  return {
    [param.key!]: val,
  }
}

const parseDataEntries = (params: any[]) => {
  return params.reduce((acc, param) => {
    return { ...acc, ...mapDataEntry(param) }
  }, {})
}

export const parseLine = (line: string, contractId: string, valid = false): Tx => {
  const fields = line.split(';')
  const rollback = Boolean(fields[fieldsEnum.rollback] && fields[fieldsEnum.rollback] === '-1')

  const raw = JSON.parse(fields[fieldsEnum.params])
  const parsed = parseDataEntries(raw)
  const diffRaw = JSON.parse(fields[fieldsEnum.diff])
  const diff = parseDataEntries(diffRaw)

  return {
    txId: fields[fieldsEnum.nestedTxId],
    type: +fields[fieldsEnum.type],
    signature: fields[fieldsEnum.signature],
    version: +fields[fieldsEnum.version],
    ts: +fields[fieldsEnum.ts],
    senderPublicKey: fields[fieldsEnum.senderPublicKey],
    fee: +fields[fieldsEnum.fee],
    feeAssetId: fields[fieldsEnum.feeAssetId],
    params: parsed,
    diff,
    raw,
    operation: parsed.operation || VotingOperation.createContract,
    extra: JSON.parse(fields[fieldsEnum.extra]),
    contractId,
    rollback,
    valid,
  }
}
