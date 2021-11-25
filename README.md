<h1 align="center"><code>@47ng/cloak</code></h1>

<div align="center">

[![NPM](https://img.shields.io/npm/v/@47ng/cloak?color=red)](https://www.npmjs.com/package/@47ng/cloak)
[![MIT License](https://img.shields.io/github/license/47ng/cloak.svg?color=blue)](https://github.com/47ng/cloak/blob/next/LICENSE)
[![Continuous Integration](https://github.com/47ng/cloak/workflows/Continuous%20Integration/badge.svg?branch=next)](https://github.com/47ng/cloak/actions)
[![Coverage Status](https://coveralls.io/repos/github/47ng/cloak/badge.svg?branch=next)](https://coveralls.io/github/47ng/cloak?branch=next)

</div>

<p align="center">
  Serialized AES-GCM 256 encryption, decryption and key management in the browser & Node.js.
</p>

## Installation

```shell
$ yarn add @47ng/cloak
# or
$ npm i @47ng/cloak
```

## CLI

The package comes with a CLI tool you can use to generate and manage keys, as
well as encrypting and decrypting data in the terminal:

```shell
$ cloak --help
Usage: cloak [options] [command]

Options:
  -h, --help                 output usage information

Commands:
  generate                   Generate an AES-GCM key
  encrypt [options] [key]    Encrypt stdin
  decrypt                    Decrypt stdin
  revoke <keyFingerprint>    Remove a key from the environment keychain
  keychain [options] [full]  List the contents of the environment keychain

# Start by generating an empty keychain and master key:
$ cloak generate
Key:          k1.aesgcm256.DL2G9PQeZ9r65J59pph6dy9Sk4fBLEZ3CTQZsandgYE=
Fingerprint:  6f28c026

Generated new empty keychain:
export CLOAK_MASTER_KEY=k1.aesgcm256.DL2G9PQeZ9r65J59pph6dy9Sk4fBLEZ3CTQZsandgYE=
export CLOAK_KEYCHAIN=v1.aesgcm256.6f28c026.yhCUkzv5gOyHJ2M_.jrGSf2_MPVofk-kSDgnYzvEy

# Copy/paste the exports into your terminal
# (the CLI does not mutate your environment directly)
$ export CLOAK_MASTER_KEY=k1.aesgcm256.DL2G9PQeZ9r65J59pph6dy9Sk4fBLEZ3CTQZsandgYE=
$ export CLOAK_KEYCHAIN=v1.aesgcm256.6f28c026.yhCUkzv5gOyHJ2M_.jrGSf2_MPVofk-kSDgnYzvEy

# Generate a key to use for encryption
$ cloak generate
Key:          k1.aesgcm256.pHLFYdaqXut62LoFbt8KV80x_YNyZPmY0kQaPhJ0Ehc=
Fingerprint:  cd38bcc4

Updated keychain:
export CLOAK_MASTER_KEY=k1.aesgcm256.DL2G9PQeZ9r65J59pph6dy9Sk4fBLEZ3CTQZsandgYE=
export CLOAK_KEYCHAIN=v1.aesgcm256.6f28c026.jr9fqMA_RfNhIjHz.lo4IfIYfZ0zxrdSns_ibWq6YX1D5AnzN-fhUF0CKVx5dRVIo0x-Atumr9WZqpHOeEIWT5bEGFKHhxGkFdwk2vg5TZQNk5Rj_jo3hnfSLaFAYncG59dB  jUkz1JE0Plq2d-GR1AbDs6P18VzOG_JrU

To use this new key as default for encryption:
export CLOAK_CURRENT_KEY=cd38bcc4

# Encrypt sdtin
$ echo 'Hello, World !' | cloak encrypt
v1.aesgcm256.cd38bcc4.yxAp2iONy7zYOhbs.X2zmGpmGw9a7tiSnyukEW8Ac-2IIcIENW5uHxtHYyA==

# Decrypt stdin
$ echo 'v1.aesgcm256.cd38bcc4.yxAp2iONy7zYOhbs.X2zmGpmGw9a7tiSnyukEW8Ac-2IIcIENW5uHxtHYyA==' | cloak decrypt
Hello, World !
```

## Programmatic Usage

```ts
// Works in the browser or in Node.js

import { generateKey, encryptString, decryptString } from '@47ng/cloak'

const demo = async () => {
  const key = generateKey()
  const cipher = await encryptString('Hello, World', key)
  const decipher = await decryptString(cipher, key)
}
```

## License

[MIT](./LICENSE) - Made with ❤️ by [François Best](https://francoisbest.com)

Using this package at work ? [Sponsor me](https://github.com/sponsors/franky47) to help with support and maintenance.
