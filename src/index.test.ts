import 'jest-extended'
import {
  generateKey,
  encryptString,
  decryptString,
  makeKeychain,
  findKeyForMessage,
  parseKey
} from './index'

test('Key generation', () => {
  const key = generateKey()
  expect(key).toStartWith('k1.aesgcm256.')
  expect(key.length).toEqual(57)
})

describe('v1 format', () => {
  test('Encrypt / decrypt', async () => {
    const key = 'k1.aesgcm256.2itF7YmMYIP4b9NNtKMhIx2axGi6aI50RcwGBiFq-VA='
    const expected = 'Hello, World !'
    const cipher = await encryptString(expected, key)
    const received = await decryptString(cipher, key)
    expect(received).toEqual(expected)
  })

  test('Encrypt empty string', async () => {
    const key = 'k1.aesgcm256.2itF7YmMYIP4b9NNtKMhIx2axGi6aI50RcwGBiFq-VA='
    const expected = ''
    const cipher = await encryptString(expected, key)
    const received = await decryptString(cipher, key)
    expect(received).toEqual(expected)
  })

  test('Decrypt known message', async () => {
    const key = 'k1.aesgcm256.2itF7YmMYIP4b9NNtKMhIx2axGi6aI50RcwGBiFq-VA='
    const cipher =
      'v1.aesgcm256.710bb0e2.F5wkSytfdVv4xvtN.8uNajc7ufhVmMFpDdzWgKMKhOY4ZR2OSv1DFjvnm'
    const expected = 'Hello, World !'
    const received = await decryptString(cipher, key)
    expect(received).toEqual(expected)
  })

  test('Decrypt known message from browser', async () => {
    const key = 'k1.aesgcm256.CO6hoJ8l1nAmXpuCcuNg-l5g3Nn63X36lBwhsNepUEY='
    const cipher =
      'v1.aesgcm256.4eb11c57.UAuPXcQZV_e40NP6.OvVOoWCXhMB_G-giNtAbDYZI0sfJomHUAW0vpxKV'
    const expected = 'Hello, World !'
    const received = await decryptString(cipher, key)
    expect(received).toEqual(expected)
  })

  test('Ciphertext & IV are rotated', async () => {
    const key = 'k1.aesgcm256.2itF7YmMYIP4b9NNtKMhIx2axGi6aI50RcwGBiFq-VA='
    const cipher1 = await encryptString('Hello, World !', key)
    const cipher2 = await encryptString('Hello, World !', key)
    expect(cipher1).not.toEqual(cipher2)
  })

  test('Fingerprinting & keychain', async () => {
    const keyA = 'k1.aesgcm256.2itF7YmMYIP4b9NNtKMhIx2axGi6aI50RcwGBiFq-VA='
    const keyB = 'k1.aesgcm256.caNwte-JDsVUATl3qCQgu9ZPuHAiJhWSOn0pcgGhwyE='
    const cipherA = await encryptString('Hello', keyA)
    const cipherB = await encryptString('Hello', keyB)
    const keychain = await makeKeychain([keyA, keyB])
    const keyForA = findKeyForMessage(cipherA, keychain)
    const keyForB = findKeyForMessage(cipherB, keychain)
    expect(keyForA).toEqual(keyA)
    expect(keyForB).toEqual(keyB)
  })

  test('Parse key', async () => {
    const key = 'k1.aesgcm256.2itF7YmMYIP4b9NNtKMhIx2axGi6aI50RcwGBiFq-VA='
    const parsedKey = await parseKey(key)
    const expected = 'Hello, World !'
    const cipher = await encryptString(expected, parsedKey)
    const received = await decryptString(cipher, parsedKey)
    expect(received).toEqual(expected)
  })
})
