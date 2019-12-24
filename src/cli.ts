#!/usr/bin/env node

import dotenv from 'dotenv'
import fs from 'fs'
import program from 'commander'
import ago from 's-ago'
import { generateKey, getKeyFingerprint, FINGERPRINT_LENGTH } from './key'
import {
  exportKeychain,
  importKeychain,
  findKeyForMessage,
  makeKeychain,
  CloakKeychain
} from './keychain'
import { encryptString, decryptString } from './message'

dotenv.config()

const env = {
  keychain: process.env.CLOAK_KEYCHAIN,
  masterKey: process.env.CLOAK_MASTER_KEY
}

const getEnvKeychain = async () => {
  if (!env.keychain || !env.masterKey) {
    return {}
  }
  return await importKeychain(env.keychain, env.masterKey)
}

const printExports = async (
  message: string,
  keychain: CloakKeychain,
  masterKey: string
) => {
  const text = [
    `\n${message}:`,
    `export CLOAK_MASTER_KEY="${masterKey}"`,
    `export CLOAK_KEYCHAIN="${await exportKeychain(keychain, masterKey)}"`
  ]
    .filter(x => !!x)
    .join('\n')
  console.log(text)
}

program
  .command('generate')
  .description('Generate an AES-GCM key')
  .action(async () => {
    const key = await generateKey()
    const fingerprint = await getKeyFingerprint(key)
    console.log('Key:         ', key)
    console.log('Fingerprint: ', fingerprint)

    // todo: print different things based on context:
    // - no master key or keychain:
    //   - the key generated is the master key
    //   - the keychain is empty
    //   - show both exports for master key and keychain
    // - master key and keychain: key rotation scenario
    //   - show exports for new keychain & new key fingerprint
    if (!env.masterKey) {
      // Use the generated key as a master key
      const keychain = await makeKeychain([])
      await printExports('Generated new empty keychain', keychain, key)
      return
    }
    const keychain = await getEnvKeychain()
    keychain[fingerprint] = {
      key,
      createdAt: Date.now()
    }
    await printExports('Updated keychain', keychain, env.masterKey)
    console.log(`
To use this new key as default for encryption:
export CLOAK_CURRENT_KEY="${fingerprint}"`)
  })

// --

program
  .command('encrypt [key]')
  .description('Encrypt stdin')
  .option('-l, --line', 'Encrypt line-by-line')
  .action(async (key, { line }) => {
    if (!key) {
      key = process.env.CLOAK_CURRENT_KEY
    }
    if (key && key.length === FINGERPRINT_LENGTH) {
      const fingerprint = key
      const keychain = await getEnvKeychain()
      if (fingerprint in keychain) {
        key = keychain[fingerprint].key
      } else {
        console.error('Missing key (not available in keychain)')
        process.exit(1)
      }
    }
    if (!key) {
      console.error('Missing key')
      process.exit(1)
    }
    const stdin = fs.readFileSync(0, 'utf-8')
    if (!line) {
      const ciphertext = await encryptString(stdin, key)
      console.log(ciphertext)
      return
    }
    for (const line of stdin.split('\n')) {
      const ciphertext = await encryptString(line, key)
      console.log(ciphertext)
    }
  })

// --

program
  .command('decrypt')
  .description('Decrypt stdin')
  .action(async () => {
    const keychain = await getEnvKeychain()
    if (!keychain) {
      // todo: Provide option to pass a cleartext key for decryption
      console.error('No keychain found and no key provided')
      process.exit(1)
    }
    // First: try from the keychain
    // Then: try with the given key
    const stdin = fs
      .readFileSync(0, 'utf-8')
      .split('\n')
      .filter(line => line.length > 0)
    for (const message of stdin) {
      const key = findKeyForMessage(message, keychain)
      const cleartext = await decryptString(message, key)
      console.log(cleartext)
    }
  })

// --

program
  .command('revoke <keyFingerprint>')
  .description('Remove a key from the environment keychain')
  .action(async keyFingerprint => {
    const keychain = await getEnvKeychain()
    if (!(keyFingerprint in keychain)) {
      console.error('No such key in env keychain')
      process.exit(1)
    }
    if (!env.masterKey) {
      console.error('Master key is missing')
      process.exit(1)
    }
    const { [keyFingerprint]: _, ...newKeychain } = keychain
    await printExports('Updated keychain', newKeychain, env.masterKey)
  })

// --

program
  .command('keychain [full]')
  .description('List the contents of the environment keychain')
  .option('-f, --full', 'Show the full keys in clear text')
  .action(async (_, { full = false } = {}) => {
    const keychain = await getEnvKeychain()
    const table = Object.keys(keychain).map(fingerprint => {
      const { key, createdAt } = keychain[fingerprint]
      const creationDate = new Date(createdAt)
      return full
        ? {
            fingerprint,
            createdAt: creationDate.toISOString(),
            key
          }
        : {
            fingerprint,
            created: ago(creationDate),
            key: '[redacted]'
          }
    })
    console.table(table)
  })

program.parse(process.argv)
