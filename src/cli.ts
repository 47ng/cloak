#!/usr/bin/env node

import fs from 'fs'
import program from 'commander'
import { generateKey, getKeyFingerprint } from './key'
import { exportKeychain, importKeychain, findKeyForMessage } from './keychain'
import { encryptString, decryptString } from './message'

const env = {
  keychain: process.env.CLOAK_KEYCHAIN,
  masterKey: process.env.CLOAK_MASTER_KEY
}

const getEnvKeychain = async () => {
  if (!env.keychain || !env.masterKey) {
    return null
  }
  return await importKeychain(env.keychain, env.masterKey)
}

program
  .command('generate')
  .description('Generate an AES-GCM key')
  .action(async () => {
    let keychain = await getEnvKeychain()
    const key = await generateKey()
    console.log(key)

    if (!keychain) {
      keychain = {}
    }
    keychain[await getKeyFingerprint(key)] = key
    console.log('New keychain:', await exportKeychain(keychain, env.masterKey!))
  })

// --

program
  .command('encrypt <key>')
  .description('Encrypt stdin with the given key or fingerprint')
  .action(async (key: string) => {
    const stdin = fs.readFileSync(0, 'utf-8')
    if (key.length === 16) {
      const fingerprint = key
      const keychain = await getEnvKeychain()
      if (keychain && fingerprint in keychain) {
        key = keychain[fingerprint]
      }
    }
    const ciphertext = await encryptString(stdin, key)
    console.log(ciphertext)
  })

// --

program
  .command('decrypt')
  .description('Decrypt stdin')
  .action(async () => {
    const stdin = fs
      .readFileSync(0, 'utf-8')
      .split('\n')
      .filter(line => line.length > 0)
    const keychain = await getEnvKeychain()
    if (!keychain) {
      console.error('No keychain found and no key provided')
      process.exit(1)
    }
    // First: try form the keychain
    // Then: try with the given key
    for (const message of stdin) {
      const key = await findKeyForMessage(message, keychain)
      const cleartext = await decryptString(message, key)
      console.log(cleartext)
    }
  })

// --

program.command('revoke <keyFingerprint>').action(async keyFingerprint => {
  const keychain = await getEnvKeychain()
  if (!keychain) {
    console.error('No environment keychain found')
    process.exit(1)
  }
  const { [keyFingerprint]: _, ...newKeychain } = keychain
  console.log(
    'New keychain:',
    await exportKeychain(newKeychain, env.masterKey!)
  )
})

// --

program
  .command('keychain [full]')
  .description('List the contents of the environment keychain')
  .option('-f, --full', 'Show the full keys in clear text')
  .action(async (_, { full = false } = {}) => {
    const keychain = await getEnvKeychain()
    if (!keychain) {
      console.error('No environment keychain found')
      process.exit(1)
    }
    console.log(
      JSON.stringify(full ? keychain : Object.keys(keychain), null, 2)
    )
  })

program.parse(process.argv)
