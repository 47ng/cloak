import { utf8 } from '@47ng/codec'
import * as NodeCrypto from 'crypto'

let nodeCrypto: typeof NodeCrypto

if (typeof window === 'undefined') {
  nodeCrypto = require('crypto')
}

export interface AesCipher {
  iv: Uint8Array
  text: Uint8Array
}

// --

export async function encryptAesGcm(
  key: CryptoKey | Uint8Array,
  message: string
): Promise<AesCipher> {
  if (typeof window === 'undefined') {
    return encryptAesGcmSync(key as Uint8Array, message)
  } else {
    // Browser - use WebCrypto
    const buf = utf8.encode(message)
    const iv = window.crypto.getRandomValues(new Uint8Array(12))
    const cipherText = await window.crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv
      },
      key as CryptoKey,
      buf
    )
    return {
      text: new Uint8Array(cipherText),
      iv
    }
  }
}

/**
 * Available only for Node.js
 */
export function encryptAesGcmSync(key: Uint8Array, message: string): AesCipher {
  // Node.js - Use native crypto module
  const iv = nodeCrypto.randomBytes(12)
  const cipher = nodeCrypto.createCipheriv('aes-256-gcm', key, iv)
  const encrypted = cipher.update(message, 'utf8')
  cipher.final()
  const tag = cipher.getAuthTag()
  return {
    // Authentication tag is the last 16 bytes
    // (for compatibility with WebCrypto serialization)
    text: new Uint8Array(Buffer.concat([encrypted, tag])),
    iv
  }
}

// --

export async function decryptAesGcm(
  key: CryptoKey | Uint8Array,
  cipher: AesCipher
): Promise<string> {
  if (typeof window === 'undefined') {
    return decryptAesGcmSync(key as Uint8Array, cipher)
  } else {
    // Browser - use WebCrypto
    const buf = await window.crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: cipher.iv
      },
      key as CryptoKey,
      cipher.text
    )
    return utf8.decode(new Uint8Array(buf))
  }
}

/**
 * Available only for Node.js.
 *
 * @param key
 * @param cipher
 * @returns
 */
export function decryptAesGcmSync(key: Uint8Array, cipher: AesCipher): string {
  // Node.js - Use native crypto module
  const decipher = nodeCrypto.createDecipheriv('aes-256-gcm', key, cipher.iv)
  // Authentication tag is the last 16 bytes
  // (for compatibility with WebCrypto serialization)
  const tagStart = cipher.text.length - 16
  const msg = cipher.text.slice(0, tagStart)
  const tag = cipher.text.slice(tagStart)
  decipher.setAuthTag(tag)
  return decipher.update(msg, undefined, 'utf8') + decipher.final('utf8')
}
