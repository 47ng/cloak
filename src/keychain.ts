import { CloakKey, getKeyFingerprint } from './key'
import {
  CloakedString,
  decryptString,
  encryptString,
  getMessageKeyFingerprint
} from './message'

interface KeychainEntry {
  key: CloakKey
  createdAt: number // timestamp
}

export type CloakKeychain = {
  [fingerprint: string]: KeychainEntry
}

export const makeKeychain = async (
  keys: CloakKey[]
): Promise<CloakKeychain> => {
  const keychain: CloakKeychain = {}
  for (const key of keys) {
    keychain[await getKeyFingerprint(key)] = {
      key,
      createdAt: Date.now()
    }
  }
  return keychain
}

/**
 * Decrypt and hydrate the given encrypted keychain
 *
 * @param encryptedKeychain - A keychain as exported by exportKeychain
 * @param masterKey - The key used to encrypt the keychain
 */
export const importKeychain = async (
  encryptedKeychain: CloakedString,
  masterKey: CloakKey
): Promise<CloakKeychain> => {
  const json = await decryptString(encryptedKeychain, masterKey)
  const keys: KeychainEntry[] = JSON.parse(json)
  const keychain: CloakKeychain = {}
  for (const { key, ...rest } of keys) {
    keychain[await getKeyFingerprint(key)] = {
      key,
      ...rest
    }
  }
  return keychain
}

/**
 * Export a serialized and encrypted version of a keychain
 *
 * @param keychain - The keychain to export
 * @param masterKey - The key to use to encrypt the keychain
 * @returns an encrypted keychain string
 */
export const exportKeychain = async (
  keychain: CloakKeychain,
  masterKey: CloakKey
): Promise<CloakedString> => {
  const entries = Object.values(keychain)
  return await encryptString(JSON.stringify(entries), masterKey)
}

export const findKeyForMessage = (
  message: CloakedString,
  keychain: CloakKeychain
): CloakKey => {
  const fingerprint = getMessageKeyFingerprint(message)
  if (!(fingerprint in keychain)) {
    throw new Error('Key is not available')
  }
  return keychain[fingerprint].key
}

export const getKeyAge = (
  fingerprint: string,
  keychain: CloakKeychain,
  now: number = Date.now()
) => {
  if (!(fingerprint in keychain)) {
    throw new Error('Key is not available')
  }
  return now - keychain[fingerprint].createdAt
}
