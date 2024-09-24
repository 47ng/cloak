import { b64 } from '@47ng/codec'
import {
  decryptAesGcm,
  decryptAesGcmSync,
  encryptAesGcm,
  encryptAesGcmSync
} from './ciphers/aes-gcm'
import {
  CloakKey,
  importKey,
  importKeySync,
  ParsedCloakKey,
  parseKey,
  parseKeySync
} from './key'

export type CloakedString = string

// Encryption --

export function encodeEncryptedString(
  fingerprint: string,
  iv: Uint8Array,
  ciphertext: Uint8Array
) {
  return [
    'v1',
    'aesgcm256',
    fingerprint,
    b64.encode(iv),
    b64.encode(ciphertext)
  ].join('.')
}

export async function encryptString(
  input: string,
  key: CloakKey | ParsedCloakKey
): Promise<CloakedString> {
  if (typeof key === 'string') {
    key = await parseKey(key, 'encrypt')
  }
  const { text: ciphertext, iv } = await encryptAesGcm(key.raw, input)
  return encodeEncryptedString(key.fingerprint, iv, ciphertext)
}

export function encryptStringSync(
  input: string,
  key: CloakKey | ParsedCloakKey
): CloakedString {
  if (typeof key === 'string') {
    key = parseKeySync(key)
  }
  const { text: ciphertext, iv } = encryptAesGcmSync(
    key.raw as Uint8Array,
    input
  )
  return encodeEncryptedString(key.fingerprint, iv, ciphertext)
}

// Decryption --

/**
 * @deprecated
 *
 * Causes stack errors on large strings, use {@link parseCloakedString} instead.
 */
export const cloakedStringRegex =
  /^v1\.aesgcm256\.(?<fingerprint>[0-9a-fA-F]{8})\.(?<iv>[a-zA-Z0-9-_]{16})\.(?<ciphertext>[a-zA-Z0-9-_]{22,})={0,2}$/

/**
 * Tests if the input string consists only of URL-safe Base64 chars
 * (e.g. using `-` and `=` instead of `+` and `/`), and is padded with `=`.
 *
 * @returns `true` if the string is a valid URL-safe Base64, else `false`.
 *
 * Adapted from <https://github.com/validatorjs/validator.js/blob/ebcca98232399b8404ca6b0ec842ab4596329d58/validator.js#L836-L845>
 * @license MIT
 * @copyright Copyright (c) 2016 Chris O'Hara <cohara87@gmail.com>
 */
function isBase64(str: string) {
  const len = str.length
  if (len % 4 === 0 && !/(^[a-z0-9-_=])/i.test(str)) {
    return false
  }
  const firstPaddingChar = str.indexOf('=')
  return (
    firstPaddingChar === -1 ||
    firstPaddingChar === len - 1 ||
    (firstPaddingChar === len - 2 && str[len - 1] === '=')
  )
}

export function parseCloakedString(input: CloakedString) {
  const [version, algorithm, fingerprint, iv, ciphertext, nothing] =
    input.split('.')

  const isCloakedString =
    version === 'v1' &&
    algorithm === 'aesgcm256' &&
    /^[0-9a-f]{8}$/i.test(fingerprint) &&
    /^[a-zA-Z0-9-_]{16}$/.test(iv) &&
    isBase64(ciphertext) &&
    ciphertext.length >= 24 &&
    nothing === undefined

  if (isCloakedString === false) {
    return false
  } else {
    return {
      groups: {
        fingerprint,
        iv,
        ciphertext
      }
    }
  }
}

export async function decryptString(
  input: CloakedString,
  key: CloakKey | ParsedCloakKey
): Promise<string> {
  const match = parseCloakedString(input)
  if (!match) {
    throw new Error(`Unknown message format: ${input}`)
  }
  const iv = match.groups.iv
  const ciphertext = match.groups!.ciphertext
  let aesKey: CryptoKey | Uint8Array
  if (typeof key === 'string') {
    aesKey = await importKey(key, 'decrypt')
  } else {
    aesKey = key.raw
  }
  return await decryptAesGcm(aesKey, {
    iv: b64.decode(iv),
    text: b64.decode(ciphertext)
  })
}

export function decryptStringSync(
  input: CloakedString,
  key: CloakKey | ParsedCloakKey
): string {
  const match = parseCloakedString(input)
  if (!match) {
    throw new Error(`Unknown message format: ${input}`)
  }
  const iv = match.groups.iv
  const ciphertext = match.groups!.ciphertext
  let aesKey: CryptoKey | Uint8Array
  if (typeof key === 'string') {
    aesKey = importKeySync(key)
  } else {
    aesKey = key.raw
  }
  return decryptAesGcmSync(aesKey as Uint8Array, {
    iv: b64.decode(iv),
    text: b64.decode(ciphertext)
  })
}

export function getMessageKeyFingerprint(message: CloakedString) {
  const match = parseCloakedString(message)
  if (!match) {
    throw new Error('Unknown message format')
  }
  return match.groups.fingerprint
}
