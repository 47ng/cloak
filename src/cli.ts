#!/usr/bin/env node

import dotenv from 'dotenv'
import fs from 'fs'
import program from 'commander'
import ago from 's-ago'
import chalk from 'chalk'
import {
  generateKey,
  getKeyFingerprint,
  FINGERPRINT_LENGTH,
  parseKey,
  serializeKey,
  CloakKey
} from './key'
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
    '',
    chalk.dim(`# ${message}:`),
    `export CLOAK_MASTER_KEY="${masterKey}"`,
    `export CLOAK_KEYCHAIN="${await exportKeychain(keychain, masterKey)}"`
  ].join('\n')
  console.log(text)
}

program
  .command('generate')
  .description('Generate an AES-GCM key')
  .action(async () => {
    const key = generateKey()
    const fingerprint = await getKeyFingerprint(key)
    console.log(chalk.bold('Key:         '), key)
    console.log(chalk.bold('Fingerprint: '), fingerprint)

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
      key: await parseKey(key),
      createdAt: Date.now()
    }
    await printExports('Updated keychain', keychain, env.masterKey)
    console.log(`
${chalk.dim('# To use this new key as default for encryption:')}
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
        console.error(
          chalk.redBright('Error: Missing key (not available in keychain)')
        )
        process.exit(1)
      }
    }
    if (!key) {
      console.error(chalk.redBright('Error: Missing key'))
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
      console.error(
        chalk.redBright('Error: No keychain found and no key provided')
      )
      process.exit(1)
    }
    const stdin = fs
      .readFileSync(0, 'utf-8')
      .split('\n')
      .filter(line => line.length > 0)
    for (const message of stdin) {
      try {
        const key = findKeyForMessage(message, keychain)
        const cleartext = await decryptString(message, key)
        console.log(cleartext)
      } catch (error) {
        console.error(chalk.redBright('Error:', error.message))
      }
    }
  })

// --

program
  .command('revoke <keyFingerprint>')
  .description('Remove a key from the environment keychain')
  .action(async keyFingerprint => {
    const keychain = await getEnvKeychain()
    if (!(keyFingerprint in keychain)) {
      console.error(chalk.redBright('Error: No such key in env keychain'))
      process.exit(1)
    }
    if (!env.masterKey) {
      console.error(chalk.redBright('Error: Master key is missing'))
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
    const table = await Promise.all(
      Object.keys(keychain).map(async fingerprint => {
        const { key, createdAt } = keychain[fingerprint]
        const creationDate = new Date(createdAt)
        return full
          ? {
              fingerprint,
              createdAt: creationDate.toISOString(),
              key: await serializeKey(key)
            }
          : {
              fingerprint,
              created: ago(creationDate),
              key: '[redacted]'
            }
      })
    )
    console.table(table)
  })

program
  .command('rotate-master-key <key>')
  .description('Generate a new master key & re-encrypt the keychain with it')
  .action(async (key: CloakKey) => {
    const keychain = await getEnvKeychain()
    const newMasterKey = key || generateKey()
    await printExports('Updated keychain', keychain, newMasterKey)
  })

program.parse(process.argv)
