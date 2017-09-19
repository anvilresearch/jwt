const crypto = require('@trust/webcrypto')
const { JWD } = require('../src')
const JWKSetCache = require('../src/JWKSetCache')
const base64url = require('base64url')
const keyto = require('@trust/keyto')
const nock = require('nock')

const privateHex = '57eba9c003d930e8233f502d8f0cc552e7ee75942b273a41c26d3bbb97b924e2'
const key = keyto.from(privateHex, 'blk')
const privateJwk = key.toJwk('private')
const publicJwk = key.toJwk('public')
const cache = new JWKSetCache()

nock('http://example.com')
  .get('/jwks')
  .reply(200, {
    keys: [
      { kty: 'EC',
        crv: 'K-256',
        x: '8f0rIY4UhA-pM1MpephSGbK2zlejAbQp8kggZxCbYmc',
        y: 'HmN6hSXf8TqnCchI0VZ0cf110ftuWLwfFJIAjwx_a0Q',
        alg: 'KS256',
        key_ops: [ 'verify' ] }
    ]
  })

let privateKey, publicKey

let payload = { iss: 'http://example.com', exp: 123456789, iat: 123456789 }
let header = { jku: 'http://example.com/jwks' }


Promise.all([
  crypto.subtle.importKey('jwk', privateJwk, { name: 'ECDSA', namedCurve: 'K-256', hash: { name: 'SHA-256' } }, true, ['sign']),
  crypto.subtle.importKey('jwk', publicJwk, { name: 'ECDSA', namedCurve: 'K-256', hash: { name: 'SHA-256' } }, true, ['verify']),
])

  // use key with JWA to create a signature
  .then(keypair => {
    let [prv, pub] = keypair
    privateKey = prv
    publicKey = pub

    return JWD.encode({ protected: header, cryptoKey: privateKey, payload, alg: 'KS256' }, { serialization: 'document' })
  })

  // verify the signature
  .then(token => {
    return JWD.verify(token, { result: 'instance' })
  })

  // look at the output
  .then(token => {
    console.error(`TOKEN FINAL VERIFICATION RESULT:`, token.verified)
    console.error(`TOKEN`)
    console.log(JSON.stringify(token, null, 2))
  })

  // look at the out
  .catch(console.log)
