/**
 * Dependencies
 */
const base64url = require('base64url')
const { JWK } = require('@trust/jwk')
const { DataError } = require('./errors')

/**
 * JOSE Signature
 */
class JOSESignature {

  /**
   * constructor
   */
  constructor (data = {}) {
    let { protectedHeader, unprotectedHeader, signature, cache } = data

    // copy properties to instance
    //
    // TODO (cs):
    // - should this be a deep copy?
    Object.assign(this, data)

    // ensure integrity protected header
    if (!protectedHeader) {
      throw new DataError('JOSESignature must define protected header')
    }

    let { alg } = protectedHeader

    // TODO
    // ensure alg?

    // ensure signature
    if (!signature && alg !== 'none') {
      throw new DataError('JOSESignature must define signature')
    }

    // ensure absence of signature
    if (signature && alg === 'none') {
      throw new DataError('Unsecured JWS must not include signature')
    }

    // ensure cache
    if (!cache && alg !== 'none') {
      throw new DataError('JOSESignature requires cache')
    }

    // TODO (cs):
    // There has to be a less janky way to ensure the unprotected header
    // is not added with undefined
    if (this.hasOwnProperty('unprotectedHeader') &&
        this['unprotectedHeader'] === undefined) {
      delete this['unprotectedHeader']
    }

    // define cache as nonenumerable
    delete this.cache
    Object.defineProperty(this, 'cache', {
      value: cache,
      enumerable: false,
      configurable: false
    })

    // make the object immutable
    Object.freeze(this)
  }

  /**
   * sign
   *
   * @description
   * This method creates complete, finalized, immutable JOSESignature objects.
   *
   * @param {Object} options
   * @param {Object} options.payload
   * @param {Object} options.unprotectedHeader
   * @param {Object} options.params
   * @param {LRU} options.cache
   * @param {JWK} options.jwk
   *
   * @returns {Promise<JOSESignature>}
   */
  static sign ({payload, unprotectedHeader, protectedHeaderParams, cache, jwk}) {
    if (!payload) {
      return Promise.reject(
        new Error('Missing payload for JOSE Signature')
      )
    }

    if (!cache) {
      return Promise.reject(
        new Error('Missing JWKSetCache for JOSE Signature')
      )
    }

    // TODO (cs)
    // ensure we have a suitable JWK instance, not just a value
    if (!jwk) {
      return Promise.reject(
        new Error('JOSE Signature requires JWK')
      )
    }

    let protectedHeader = jwk.getProtectedHeader(protectedHeaderParams)
    let b64p = base64url(JSON.stringify(payload))
    let b64h = base64url(JSON.stringify(protectedHeader))
    let input = `${b64h}.${b64p}`

    return jwk.sign(input)
      .then(signature => new JOSESignature({
        unprotectedHeader,
        protectedHeader,
        signature,
        cache
      }))
  }

  /**
   * verify
   *
   * @description
   * Verifies a JOSE Signature object for a given payload. If no key is provided,
   * verify will try to get a key from the cache.
   *
   * @param {Object} payload
   * @param {JWK|CryptoKey} keyHint
   *
   * @returns {Promise<Boolean>}
   */
  verify (payload, keyHint) {
    let { protectedHeader, signature, cache } = this
    let { alg, kid, jku, jwc } = protectedHeader

    // Validate presence of "alg"
    if (!alg) {
      return Promise.reject(
        new DataError('Missing "alg" in protected header')
      )
    }

    // Invalid Unsecured JWS
    // NOTE: this is convered in the constructor as well
    //if (alg === 'none' && signature) {
    //  return Promise.reject(
    //    new GoFuckYourselfHNError()
    //  )
    //}

    // Valid Unsecured JWS
    if (alg === 'none') {
      return Promise.resolve(true)
    }

    // Build the signing input for comparison
    let b64h = base64url(JSON.stringify(protectedHeader))
    let b64p = base64url(JSON.stringify(payload))
    let signingInput = `${b64h}.${b64p}`

    // explicitly passed a JWK instance with verify method
    if (keyHint instanceof JWK) {
      return keyHint.verify(signingInput, signature)
    }

    // passed a value for a single key that can be imported with JWK
    // OR handle other usable key types such as CryptoKey
    if (keyHint) {
      return JWK.importKey(keyHint).then(jwk => this.verify(payload, jwk))
    }

    // certificate chain
    if (Array.isArray(jwc)) {}

    // certificate
    if (jwc) {}

    // remote jwk
    if (kid && jku) {
      return cache.getJwk(kid, jku).then(jwk => this.verify(payload, jwk))
    }
  }

}

/**
 * Export
 */
module.exports = JOSESignature
