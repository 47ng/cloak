import { encryptString, decryptString } from './index'

describe('v1 format', () => {
  test('encrypt/decrypt', async () => {
    const key = 'k1.aesgcm256.2itF7YmMYIP4b9NNtKMhIx2axGi6aI50RcwGBiFq-VA='
    const expected = 'Hello, World !'
    const cipher = await encryptString(expected, key)
    const received = await decryptString(cipher, key)
    expect(received).toEqual(expected)
  })
})
