import { b64 } from './utility/codec'
import { encryptAesGcm, decryptAesGcm } from './ciphers/aes-gcm'
import { importKey, getKeyFingerprint, CloakKey } from './key'

export type CloakedString = string

export const encryptString = async (
  input: string,
  key: CloakKey
): Promise<CloakedString> => {
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
}

export const decryptString = async (
  input: CloakedString,
  key: CloakKey
): Promise<string> => {
  if (!input.startsWith('v1.')) {
    throw new Error('Unknown format')
  }
  const [_, algo, fingerprint, iv, ciphertext] = input.split('.')
  if (algo !== 'aesgcm256') {
    throw new Error('Unsupported cipher')
  }
  const aesKey = await importKey(key, 'decrypt')
  return await decryptAesGcm(aesKey, {
    iv: b64.decode(iv),
    text: b64.decode(ciphertext)
  })
}

export const getMessageKeyFingerprint = (message: CloakedString) => {
  if (!message.startsWith('v1.')) {
    throw new Error('Unknown format')
  }
  const [_, algo, fingerprint] = message.split('.')
  if (algo !== 'aesgcm256') {
    throw new Error('Unsupported cipher')
  }
  return fingerprint
}
