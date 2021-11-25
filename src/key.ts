import { b64, hex, utf8 } from '@47ng/codec'
import * as NodeCrypto from 'crypto'

let nodeCrypto: typeof NodeCrypto

if (typeof window === 'undefined') {
  nodeCrypto = require('crypto')
}

export const FINGERPRINT_LENGTH = 8

export const cloakKeyRegex = /^k1\.aesgcm256\.(?<key>[a-zA-Z0-9-_]{43}=?)$/

/**
 * Serialized representation of a Cloak key.
 *
 * Suported key formats:
 *
 * ## Version 1
 * Text format: `k1.{algo}.{rawKey}`
 * - `algo`   : Only `aesgcm256` is supported (AES-GCM with a 256 bit key).
 * - `rawKey` : base64url-encoded raw export of the WebCrypto key.
 */
export type CloakKey = string

export interface ParsedCloakKey {
  raw: Uint8Array | CryptoKey
  fingerprint: string
}

export function formatKey(raw: Uint8Array) {
  return ['k1', 'aesgcm256', b64.encode(raw)].join('.')
}

export async function parseKey(
  key: CloakKey,
  usage?: 'encrypt' | 'decrypt'
): Promise<ParsedCloakKey> {
  return {
    raw: await importKey(key, usage),
    fingerprint: await getKeyFingerprint(key)
  }
}

/**
 * Sync version of parseKey, only available for Node.js
 */
export function parseKeySync(key: CloakKey): ParsedCloakKey {
  return {
    raw: importKeySync(key),
    fingerprint: getKeyFingerprintSync(key)
  }
}

export async function serializeKey(key: ParsedCloakKey): Promise<CloakKey> {
  return (key.raw as CryptoKey).algorithm
    ? await exportCryptoKey(key.raw as CryptoKey)
    : formatKey(key.raw as Uint8Array)
}

/**
 * Generate an AES-GCM 256 bit serialized key.
 */
export function generateKey(): CloakKey {
  const keyLength = 32 // bytes
  if (typeof window === 'undefined') {
    // Node.js
    const key = nodeCrypto.randomBytes(keyLength)
    return formatKey(key)
  } else {
    // Browser - use WebCrypto
    const key = window.crypto.getRandomValues(new Uint8Array(keyLength))
    return formatKey(key)
  }
}

// --

/**
 * Serialize a WebCrypto key into a compact text format.
 *
 * @param key - An exportable WebCrypto key
 */
export async function exportCryptoKey(key: CryptoKey): Promise<CloakKey> {
  const algo = key.algorithm as AesKeyAlgorithm
  if (algo.name !== 'AES-GCM' || algo.length !== 256) {
    throw new Error('Unsupported key type')
  }
  const raw = await window.crypto.subtle.exportKey('raw', key)
  return formatKey(new Uint8Array(raw))
}

// -----------------------------------------------------------------------------

/**
 * Internal method: de-serialize a Cloak key into a WebCrypto key.
 * Note that the imported key cannot be re-exported, to limit leakage.
 *
 * @param key - Serialized Cloak key
 * @param usage - What the key is for (encryption or decryption)
 */
export async function importKey(
  key: CloakKey,
  usage?: 'encrypt' | 'decrypt'
): Promise<CryptoKey | Uint8Array> {
  const match = key.match(cloakKeyRegex)
  if (!match) {
    throw new Error('Unknown key format')
  }
  const raw = b64.decode(match.groups!.key)
  if (typeof window === 'undefined') {
    // Node.js
    return raw
  } else {
    // Browser
    return await window.crypto.subtle.importKey(
      'raw',
      raw,
      {
        name: 'AES-GCM',
        length: 256
      },
      true,
      usage ? [usage] : ['encrypt', 'decrypt']
    )
  }
}

/**
 * Internal method: de-serialize a Cloak key into an Uint8Array.
 *
 * Available only on Node.js
 *
 * @param key - Serialized Cloak key
 */
export function importKeySync(key: CloakKey): Uint8Array {
  const match = key.match(cloakKeyRegex)
  if (!match) {
    throw new Error('Unknown key format')
  }
  return b64.decode(match.groups!.key)
}

/**
 * Internal method: calculate a key fingerprint
 * Fingerprint is the first 8 bytes of the SHA-256 of the
 * serialized key text, represented as an hexadecimal string.
 */
export async function getKeyFingerprint(key: CloakKey): Promise<string> {
  const data = utf8.encode(key)
  if (typeof window === 'undefined') {
    // Node.js
    const hash = nodeCrypto.createHash('sha256')
    hash.update(data)
    return hash.digest('hex').slice(0, FINGERPRINT_LENGTH)
  } else {
    // Browser - use WebCrypto
    const hash = await window.crypto.subtle.digest('SHA-256', data)
    return hex.encode(new Uint8Array(hash)).slice(0, FINGERPRINT_LENGTH)
  }
}

/**
 * Internal method: calculate a key fingerprint
 * Fingerprint is the first 8 bytes of the SHA-256 of the
 * serialized key text, represented as an hexadecimal string.
 */
export function getKeyFingerprintSync(key: CloakKey): string {
  const data = utf8.encode(key)
  const hash = nodeCrypto.createHash('sha256')
  hash.update(data)
  return hash.digest('hex').slice(0, FINGERPRINT_LENGTH)
}
