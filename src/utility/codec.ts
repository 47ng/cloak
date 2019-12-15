import { encodeURLSafe, decodeURLSafe } from '@stablelib/base64'
import { encode as encodeUtf8, decode as decodeUtf8 } from '@stablelib/utf8'
import { encode as encodeHex, decode as decodeHex } from '@stablelib/hex'

export const b64 = {
  urlSafe: (str: string) => str.replace(/\+/g, '-').replace(/\//g, '_'),
  encode: encodeURLSafe,
  decode: (base64: string) => decodeURLSafe(b64.urlSafe(base64))
}

export const utf8 = {
  encode: encodeUtf8,
  decode: decodeUtf8
}

export const hex = {
  encode: (data: Uint8Array) => encodeHex(data, true),
  decode: (hex: string) => decodeHex(hex)
}

// --

export const hexToBase64url = (input: string) => {
  return b64.encode(hex.decode(input))
}

export const base64ToHex = (base64: string) => {
  return hex.encode(b64.decode(base64))
}

// --

export type Encoder = (buffer: Uint8Array) => string
export type Decoder = (string: string) => Uint8Array
export type Encoding = 'base64' | 'utf8' | 'hex'
export type Encoders = {
  [key in Encoding]: Encoder
}
export type Decoders = {
  [key in Encoding]: Decoder
}

export const encoders: Encoders = {
  base64: b64.encode,
  utf8: utf8.decode,
  hex: hex.encode
}
export const decoders: Decoders = {
  base64: b64.decode,
  utf8: utf8.encode,
  hex: hex.decode
}
