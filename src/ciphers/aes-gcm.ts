import webcrypto from '../utility/webcrypto'
import { utf8 } from '../utility/codec'

export interface AesCipher {
  iv: Uint8Array
  text: Uint8Array
}

// --

export const encryptAesGcm = async (
  key: CryptoKey,
  message: string
): Promise<AesCipher> => {
  const buf = utf8.encode(message)
  const iv = webcrypto.getRandomValues(new Uint8Array(12))
  const cipherText = await webcrypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv
    },
    key,
    buf
  )
  return {
    text: new Uint8Array(cipherText),
    iv
  }
}

export const decryptAesGcm = async (
  key: CryptoKey,
  cipher: AesCipher
): Promise<string> => {
  const buf = await webcrypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: cipher.iv
    },
    key,
    cipher.text
  )
  return utf8.decode(new Uint8Array(buf))
}
