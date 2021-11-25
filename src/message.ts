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

export const cloakedStringRegex =
  /^v1\.aesgcm256\.(?<fingerprint>[0-9a-fA-F]{8})\.(?<iv>[a-zA-Z0-9-_]{16})\.(?<ciphertext>[a-zA-Z0-9-_]{22,})={0,2}$/

export async function decryptString(
  input: CloakedString,
  key: CloakKey | ParsedCloakKey
): Promise<string> {
  const match = input.match(cloakedStringRegex)
  if (!match) {
    throw new Error(`Unknown message format: ${input}`)
  }
  const iv = match.groups!.iv
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
  const match = input.match(cloakedStringRegex)
  if (!match) {
    throw new Error(`Unknown message format: ${input}`)
  }
  const iv = match.groups!.iv
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
  const match = message.match(cloakedStringRegex)
  if (!match) {
    throw new Error('Unknown message format')
  }
  return match.groups!.fingerprint
}
