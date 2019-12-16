#!/usr/bin/env node

import dotenv from 'dotenv'
import fs from 'fs'
import program from 'commander'
import { generateKey, getKeyFingerprint } from './key'
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
    console.log(key)

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
    keychain[await getKeyFingerprint(key)] = key
    await printExports('Updated keychain', keychain, env.masterKey)
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
      if (fingerprint in keychain) {
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
    console.log(
      JSON.stringify(full ? keychain : Object.keys(keychain), null, 2)
    )
  })

program.parse(process.argv)
