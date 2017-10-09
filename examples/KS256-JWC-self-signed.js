const crypto = require('@trust/webcrypto')
const { JWT } = require('../src')
const base64url = require('base64url')
const keyto = require('@trust/keyto')
const { JWK } = require('@trust/jwk')
const nock = require('nock')

const privateHex = '57eba9c003d930e8233f502d8f0cc552e7ee75942b273a41c26d3bbb97b924e2'
const key = keyto.from(privateHex, 'blk')
const privateJwk = key.toJwk('private')
privateJwk.key_ops = ['sign']
const publicJwk = key.toJwk('public')
publicJwk.key_ops = ['verify']

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
  JWK.importKey({ ...privateJwk, alg: 'KS256' }),
  JWK.importKey({ ...publicJwk, alg: 'KS256' }),
])

  // use key with JWA to create a signature
  .then(keypair => {
    let [prv, pub] = keypair
    privateKey = prv
    publicKey = pub

    return JWT.encode({ protected: header, jwk: privateKey, payload: { ...publicJwk, alg: 'KS256' }, serialization: 'compact' })
  })

  .then(console.log)
  .catch(console.error)
