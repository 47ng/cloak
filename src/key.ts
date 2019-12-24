import webcrypto from './utility/webcrypto'
import { utf8, b64, hex } from './utility/codec'

export const FINGERPRINT_LENGTH = 8

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

/**
 * Generate an AES-GCM 256bit serialized key.
 */
export const generateKey = async (): Promise<CloakKey> => {
  const key = await webcrypto.subtle.generateKey(
    {
      name: 'AES-GCM',
      length: 256
    },
    true,
    ['encrypt', 'decrypt']
  )
  return await exportKey(key)
}

// --

/**
 * Serialize a WebCrypto key into a compact text format.
 *
 * @param key - An exportable WebCrypto key
 */
export const exportKey = async (key: CryptoKey): Promise<CloakKey> => {
  const algo = key.algorithm as AesKeyAlgorithm
  if (algo.name !== 'AES-GCM' || algo.length !== 256) {
    throw new Error('Unsupported key type')
  }
  const raw = await webcrypto.subtle.exportKey('raw', key)
  return ['k1', 'aesgcm256', b64.encode(new Uint8Array(raw))].join('.')
}

// -----------------------------------------------------------------------------

/**
 * Internal method: de-serialize a Cloak key into a WebCrypto key.
 * Note that the imported key cannot be re-exported, to limit leakage.
 *
 * @param key - Serialized Cloak key
 * @param usage - What the key is for (encryption or decryption)
 */
export const importKey = async (
  key: CloakKey,
  usage: 'encrypt' | 'decrypt'
) => {
  if (!key.startsWith('k1.')) {
    throw new Error('Unknown key format')
  }
  const [_, algorithm, secret] = key.split('.')
  if (algorithm !== 'aesgcm256') {
    throw new Error('Unsupported key type')
  }
  const raw = b64.decode(secret)
  return await webcrypto.subtle.importKey(
    'raw',
    raw,
    {
      name: 'AES-GCM',
      length: 256
    },
    false, // Cannot re-export
    [usage]
  )
}

/**
 * Internal method: calculate a key fingerprint
 * Fingerprint is the first 8 bytes of the SHA-256 of the
 * serialized key text, represented as an hexadecimal string.
 * @param key -
 */
export const getKeyFingerprint = async (key: CloakKey): Promise<string> => {
  const data = utf8.encode(key)
  const hash = await webcrypto.subtle.digest('SHA-256', data)
  return hex.encode(new Uint8Array(hash)).slice(0, FINGERPRINT_LENGTH)
}
