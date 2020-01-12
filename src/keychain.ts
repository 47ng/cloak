import { CloakKey, ParsedCloakKey, parseKey, serializeKey } from './key'
import {
  CloakedString,
  decryptString,
  encryptString,
  getMessageKeyFingerprint
} from './message'

interface KeychainEntry {
  key: ParsedCloakKey
  createdAt: number // timestamp
}

interface SerializedKeychainEntry {
  key: CloakKey
  createdAt: number // timestamp
}

export type CloakKeychain = {
  [fingerprint: string]: KeychainEntry
}

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
 * Decrypt and hydrate the given encrypted keychain
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
 * Export a serialized and encrypted version of a keychain
 *
 * @param keychain - The keychain to export
 * @param masterKey - The key to use to encrypt the keychain
 * @returns an encrypted keychain string
 */
export async function exportKeychain(
  keychain: CloakKeychain,
  masterKey: CloakKey
): Promise<CloakedString> {
  const rawEntries: KeychainEntry[] = Object.values(keychain)
  const entries: SerializedKeychainEntry[] = []
  for (const entry of rawEntries) {
    entries.push({
      key: await serializeKey(entry.key),
      createdAt: entry.createdAt
    })
  }
  return await encryptString(JSON.stringify(entries), masterKey)
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
