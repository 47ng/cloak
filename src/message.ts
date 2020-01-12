import { b64 } from '@47ng/codec'
import { encryptAesGcm, decryptAesGcm } from './ciphers/aes-gcm'
import { importKey, getKeyFingerprint, CloakKey, ParsedCloakKey } from './key'

export type CloakedString = string

export async function encryptString(
  input: string,
  key: CloakKey | ParsedCloakKey
): Promise<CloakedString> {
  if (typeof key === 'string') {
    const aesKey = await importKey(key, 'encrypt')
    const fingerprint = await getKeyFingerprint(key)
    const { text: ciphertext, iv } = await encryptAesGcm(aesKey, input)
    return [
      'v1',
      'aesgcm256',
      fingerprint,
      b64.encode(iv),
      b64.encode(ciphertext)
    ].join('.')
  } else {
    const { text: ciphertext, iv } = await encryptAesGcm(key.raw, input)
    return [
      'v1',
      'aesgcm256',
      key.fingerprint,
      b64.encode(iv),
      b64.encode(ciphertext)
    ].join('.')
  }
}

export async function decryptString(
  input: CloakedString,
  key: CloakKey | ParsedCloakKey
): Promise<string> {
  if (!input.startsWith('v1.')) {
    throw new Error('Unknown message format')
  }
  const [_, algo, fingerprint, iv, ciphertext] = input.split('.')
  if (algo !== 'aesgcm256') {
    throw new Error('Unsupported cipher')
  }

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

export function getMessageKeyFingerprint(message: CloakedString) {
  if (!message.startsWith('v1.')) {
    throw new Error('Unknown message format')
  }
  const [_, algo, fingerprint] = message.split('.')
  if (algo !== 'aesgcm256') {
    throw new Error('Unsupported cipher')
  }
  return fingerprint
}
