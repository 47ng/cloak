const webcrypto: Crypto = (() => {
  if (typeof window === 'undefined') {
    // Server side
    const NodeWebCrypto = require('node-webcrypto-ossl')
    return new NodeWebCrypto()
  } else {
    return window.crypto
  }
})()

export default webcrypto
