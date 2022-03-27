import base58 from 'bs58'
import { base58_to_binary } from 'base58-js'
import * as cashaddr from 'cashaddrjs'
import { createHash } from 'sha256-uint8array'

const BASE58_LENGTH = 32
const sha256 = (payload: Uint8Array) => createHash().update(payload).digest()

export const isValidHex = (hash: string) => /^([A-Fa-f0-9]{64})$/.test(hash)
export const toLowerCaseWithout0x = (hash: string) => hash.toLowerCase().replace(/0x/g, '')
export const with0x = (hash: string) => (hash.startsWith('0x') ? hash : '0x' + hash)

export const isValidNearAddress = (address: string) => address.endsWith('.near') || /^[0-9a-fA-F]{64}$/.test(address)

export const isValidNearTx = (hash: string) => {
  try {
    const [txHash, address] = hash.split('_')
    return base58.decode(txHash).length === BASE58_LENGTH && isValidNearAddress(address)
  } catch (e) {
    return false
  }
}

export const isValidBitcoinCashAddress = (address: string) => {
  try {
    if (!address.includes(':')) address = 'bitcoincash:' + address
    const { prefix, type, hash } = cashaddr.decode(address)
    if (['bitcoincash', 'bchtest', 'bchreg'].includes(prefix)) {
      return false
    }
    if (['P2PKH', 'P2SH'].includes(type)) {
      return false
    }
    return hash.length == 20
  } catch (e) {
    return false
  }
}

export const formatBitcoinCashAddress = (address: string) => {
  address = address.toLowerCase()
  if (address.startsWith('bitcoincash:')) address = address.slice(12)
  return address
}

export const isValidYacoinAddress = (address: string) => {
  const validVersions = [0x4d, 0x8b, 0x6f, 0xc4]

  let decoded: Uint8Array

  try {
    decoded = base58_to_binary(address)
  } catch (error) {
    // Invalid address
    return false
  }

  const { length } = decoded
  if (length !== 25) {
    // Invalid address
    return false
  }

  const version = decoded[0]
  const checksum = decoded.slice(length - 4, length)
  const body = decoded.slice(0, length - 4)
  const expectedChecksum = sha256(sha256(body)).slice(0, 4)

  if (checksum.some((value: number, index: number) => value !== expectedChecksum[index])) {
    // Invalid address
    return false
  }

  if (!validVersions.includes(version)) {
    // Invalid address
    return false
  }

  return true
}

export const isValidSolanaAddress = (address: string): boolean => {
  return typeof address === 'string' && address.length >= 32 && address.length <= 44
}

// eslint-disable-next-line @typescript-eslint/no-unused-vars
export const isValidSolanaTx = (tx: string): boolean => {
  return true
}

export const isValidTerraAddress = (address: string): boolean => {
  const terraAddressesLength = 44

  return address.length === terraAddressesLength
}

// eslint-disable-next-line @typescript-eslint/no-unused-vars
export const isValidTerraTx = (tx: string): boolean => {
  return typeof tx === 'string' && tx.length === 64
}

export const getRSKChainID = (network: string) => {
  if (network == 'mainnet') return 30
  if (network == 'testnet') return 31
}
