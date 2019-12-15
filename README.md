# `cloak`

[![MIT License](https://img.shields.io/github/license/47ng/cloak.svg?color=blue)](https://github.com/47ng/cloak/blob/master/LICENSE)
[![Travis CI Build](https://img.shields.io/travis/com/47ng/cloak.svg)](https://travis-ci.com/47ng/cloak)
[![Average issue resolution time](https://isitmaintained.com/badge/resolution/47ng/cloak.svg)](https://isitmaintained.com/project/47ng/cloak)
[![Number of open issues](https://isitmaintained.com/badge/open/47ng/cloak.svg)](https://isitmaintained.com/project/47ng/cloak)

Serialized AES-GCM 256 encryption, decryption and key management in the browser & Node.js.

## Installation

```shell
$ yarn add @47ng/cloak
# or
$ npm i @47ng/cloak
```

## Documentation

```ts
import { generateKey, encryptString, decryptString } from '@47ng/cloak'

const demo = async () => {
  const key = await generateKey()
  const cipher = await encryptString('Hello, World', key)
  const decipher = await decryptString(cipher, key)
}
```

## License

[MIT](https://github.com/47ng/cloak/blob/master/LICENSE) - Made with ❤️ by [François Best](https://francoisbest.com).
