import 'regenerator-runtime/runtime'
import { generateKey, encryptString, decryptString } from '../src'

const test = async () => {
  const key = generateKey()
  const expected = 'Hello, World !'
  const cipher = await encryptString(expected, key)
  console.info('Browser cipher', {
    key,
    cipher
  })
  let received = await decryptString(cipher, key)
  if (received !== expected) {
    console.error('Failed to encrypt/decrypt')
    return
  }

  const nodeKey = 'k1.aesgcm256.2itF7YmMYIP4b9NNtKMhIx2axGi6aI50RcwGBiFq-VA='
  const nodeMessage =
    'v1.aesgcm256.710bb0e2.F5wkSytfdVv4xvtN.8uNajc7ufhVmMFpDdzWgKMKhOY4ZR2OSv1DFjvnm'
  received = await decryptString(nodeMessage, nodeKey)

  if (received !== expected) {
    console.error('Failed to decrypt message from Node')
    return
  }
  console.info('All tests passed')
}

test()
