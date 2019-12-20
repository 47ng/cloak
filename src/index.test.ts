import {
  encryptString,
  decryptString,
  makeKeychain,
  findKeyForMessage
} from './index'

describe('v1 format', () => {
  test('Encrypt / decrypt', async () => {
    const key = 'k1.aesgcm256.2itF7YmMYIP4b9NNtKMhIx2axGi6aI50RcwGBiFq-VA='
    const expected = 'Hello, World !'
    const cipher = await encryptString(expected, key)
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
})
