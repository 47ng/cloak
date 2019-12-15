import { CloakKey, getKeyFingerprint } from './key'
import {
  CloakedString,
  decryptString,
  encryptString,
  getMessageKeyFingerprint
} from './message'

export type CloakKeychain = {
  [fingerprint: string]: CloakKey
}

export const makeKeychain = async (
  keys: CloakKey[]
): Promise<CloakKeychain> => {
  const keychain: CloakKeychain = {}
  for (const key of keys) {
    keychain[await getKeyFingerprint(key)] = key
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
  const keyList = await decryptString(encryptedKeychain, masterKey)
  const keys = keyList.split(',')
  const keychain: CloakKeychain = {}
  for (const key of keys) {
    keychain[await getKeyFingerprint(key)] = key
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
  const keyList = Object.values(keychain).join(',')
  return encryptString(keyList, masterKey)
}

export const findKeyForMessage = async (
  message: CloakedString,
  keychain: CloakKeychain
): Promise<CloakKey> => {
  const fingerprint = getMessageKeyFingerprint(message)
  if (!Object.keys(keychain).includes(fingerprint)) {
    throw new Error('Key is not available')
  }
  return keychain[fingerprint]
}
