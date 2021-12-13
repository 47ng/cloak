import {
  CloakKey,
  formatKey,
  ParsedCloakKey,
  parseKey,
  parseKeySync,
  serializeKey
} from './key'
import {
  CloakedString,
  decryptString,
  decryptStringSync,
  encryptString,
  encryptStringSync,
  getMessageKeyFingerprint
} from './message'

export interface KeychainEntry {
  key: ParsedCloakKey
  createdAt: number // timestamp
  label?: string
}

interface SerializedKeychainEntry {
  key: CloakKey
  createdAt: number // timestamp
  label?: string
}

export type CloakKeychain = {
  [fingerprint: string]: KeychainEntry
}

/**
 * Create a keychain holding the given list of keys.
 *
 * Runs everywhere (Node.js & browser).
 *
 * @param keys a list of keys to include in the keychain
 */
export async function makeKeychain(keys: CloakKey[]): Promise<CloakKeychain> {
  const keychain: CloakKeychain = {}
  for (const key of keys) {
    const parsedKey = await parseKey(key)
    keychain[parsedKey.fingerprint] = {
      key: parsedKey,
      createdAt: Date.now()
    }
  }
  return keychain
}

/**
 * Create a keychain holding the given list of keys.
 *
 * Available only for Node.js
 *
 * @param keys a list of keys to include in the keychain
 */
export function makeKeychainSync(keys: CloakKey[]): CloakKeychain {
  const keychain: CloakKeychain = {}
  for (const key of keys) {
    const parsedKey = parseKeySync(key)
    keychain[parsedKey.fingerprint] = {
      key: parsedKey,
      createdAt: Date.now()
    }
  }
  return keychain
}

/**
 * Decrypt and hydrate the given encrypted keychain.
 *
 * Runs everywhere (Node.js & browser).
 *
 * @param encryptedKeychain - A keychain as exported by exportKeychain
 * @param masterKey - The key used to encrypt the keychain
 */
export async function importKeychain(
  encryptedKeychain: CloakedString,
  masterKey: CloakKey
): Promise<CloakKeychain> {
  const json = await decryptString(encryptedKeychain, masterKey)
  const keys: SerializedKeychainEntry[] = JSON.parse(json)
  const keychain: CloakKeychain = {}
  for (const { key, ...rest } of keys) {
    const parsedKey = await parseKey(key)
    keychain[parsedKey.fingerprint] = {
      key: parsedKey,
      ...rest
    }
  }
  return keychain
}

/**
 * Decrypt and hydrate the given encrypted keychain.
 *
 * Available only for Node.js
 *
 * @param encryptedKeychain - A keychain as exported by exportKeychain
 * @param masterKey - The key used to encrypt the keychain
 */
export function importKeychainSync(
  encryptedKeychain: CloakedString,
  masterKey: CloakKey
): CloakKeychain {
  const json = decryptStringSync(encryptedKeychain, masterKey)
  const keys: SerializedKeychainEntry[] = JSON.parse(json)
  const keychain: CloakKeychain = {}
  for (const { key, ...rest } of keys) {
    const parsedKey = parseKeySync(key)
    keychain[parsedKey.fingerprint] = {
      key: parsedKey,
      ...rest
    }
  }
  return keychain
}

/**
 * Export a serialized and encrypted version of a keychain.
 *
 * Runs everywhere (Node.js & browser).
 *
 * @param keychain - The keychain to export
 * @param masterKey - The key to use to encrypt the keychain
 * @returns an encrypted keychain string
 */
export async function exportKeychain(
  keychain: CloakKeychain,
  masterKey: CloakKey | ParsedCloakKey
): Promise<CloakedString> {
  const rawEntries: KeychainEntry[] = Object.values(keychain)
  const entries: SerializedKeychainEntry[] = []
  for (const entry of rawEntries) {
    entries.push({
      key: await serializeKey(entry.key),
      createdAt: entry.createdAt,
      label: entry.label
    })
  }
  return await encryptString(JSON.stringify(entries), masterKey)
}

/**
 * Export a serialized and encrypted version of a keychain
 *
 * Available only for Node.js
 *
 * @param keychain - The keychain to export
 * @param masterKey - The key to use to encrypt the keychain
 * @returns an encrypted keychain string
 */
export function exportKeychainSync(
  keychain: CloakKeychain,
  masterKey: CloakKey | ParsedCloakKey
): CloakedString {
  const rawEntries: KeychainEntry[] = Object.values(keychain)
  const entries: SerializedKeychainEntry[] = []
  for (const entry of rawEntries) {
    entries.push({
      key: formatKey(entry.key.raw as Uint8Array),
      createdAt: entry.createdAt,
      label: entry.label
    })
  }
  return encryptStringSync(JSON.stringify(entries), masterKey)
}

export function findKeyForMessage(
  message: CloakedString,
  keychain: CloakKeychain
): ParsedCloakKey {
  const fingerprint = getMessageKeyFingerprint(message)
  if (!(fingerprint in keychain)) {
    throw new Error('Key is not available')
  }
  return keychain[fingerprint].key
}

export function getKeyAge(
  fingerprint: string,
  keychain: CloakKeychain,
  now: number = Date.now()
) {
  if (!(fingerprint in keychain)) {
    throw new Error('Key is not available')
  }
  return now - keychain[fingerprint].createdAt
}
