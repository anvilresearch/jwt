'use strict'

/**
 * Dependencies
 */
const { JWKSet } = require('@trust/jwk')

/**
 * MAX
 */
const MAX = 100

/**
 * JWKSetCache
 */
class JWKSetCache {

  /**
   * constructor
   */
  constructor (options = {}) {
    this.jwkSets = {}
    this.recent = []
    this.store = options.store || null
    this.max = options.max || MAX
  }

  /**
   * getJwk
   *
   * @description
   * Gets a JWK identified by `kid` from a JWKSet identified
   * by `jku`. May result in network request or database
   * retrieval.
   *
   * @param {string} kid
   * @param {string} jku
   *
   * @returns {Promise<JWK>}
   */
  getJwk (kid, jku) {
    return Promise.resolve()
      .then(() => this.getJwks(jku))
      .then(jwks => this.getJwkFromJwks(jwks, jku, kid))
  }

  /**
   * getJwks
   *
   * @description
   * Gets a JWKSet idenfified by `jku`. May result in network
   * request or database retrieval.
   *
   * @param {string} jku
   * @returns {Promise<JWKSet>}
   */
  getJwks (jku) {
    return Promise.resolve()
      .then(() => this.getJwksFromCache(jku))
      .then(jwks => this.getJwksFromStore(jwks, jku))
      .then(jwks => this.getJwksFromNetwork(jwks, jku))
      .then(jwks => this.cacheJwks(jwks))
  }

  /**
   * getJwksFromCache
   *
   * @description
   * Gets a JWKSet instance from in memory cache.
   *
   * @param {string} jku
   * @returns {Promise<string|null>}
   */
  getJwksFromCache (jku) {
    let cache = this.jwkSets
    let jwks = cache[jku] || null

    return Promise.resolve(jwks)
  }

  /**
   * getJwksFromStore
   *
   * @description
   * Gets a JWK Set from the database and import to
   * JWKSet instance.
   *
   * @param {JWKSet|null} jwks
   * @param {string} jku
   *
   * @return {Promise<JWKSet|null>}
   */
  getJwksFromStore (jwks, jku) {
    let { store } = this

    // pass through
    if (jwks || !store) {
      return Promise.resolve(jwks)
    }

    // get from the persisted cache
    return store.get(jku).then(data => {
      if (!data) { return null }
      return JWKSet.importKeys(data)
    })

    // pouchdb rejects with a 404
    .catch(err => {
      if (err.status === 404) {
        return null
      }

      throw err
    })
  }

  /**
   * getJwksFromNetwork
   *
   * @description
   * Gets a JWK Set from the network and import to
   * JWKSet instance.
   *
   * @param {JWKSet|null} jwks
   *
   */
  getJwksFromNetwork (jwks, jku) {
    let { store } = this

    if (jwks) {
      return Promise.resolve(jwks)
    }

    return JWKSet.importKeys(jku)
      .then(jwks => {
        let data = Object.assign({ _id: jku }, jwks)

        if (store) {
          return store.put(data)
            .then(() => jwks)
            .catch(err => {
              if (err.status === 409) {
                return store.get(jku).then(({_rev}) => {
                  data._rev = _rev
                  return store.put(data).then(() => jwks)
                })
              }

              throw err
            })
        }
      })
      .catch(err => {
        // we don't care downstream *why* it couldn't be fetched?
        // only that we don't have a JWK Set...
        // shouldn't interrupt program.
        // paper over it? should we log something?
        // JWKSet.importKeys should give typed error.
        if (err.message.match('Failed to fetch remote JWKSet')) {
          return null
        }

        throw err
      })
  }

  /**
   * cacheJwks
   *
   * @description
   * Reorders the LRU Cache and removes least recently used items.
   *
   * @param {JWKSet|null} jwks
   * @param {string} jku
   *
   * @returns {Promise<JWKSet>}
   */
  cacheJwks (jwks, jku) {
    let { jwkSets, recent, max } = this

    if (!jwks) {
      return Promise.reject(new Error('JWK Set not found'))
    }

    if (recent.includes(jku)) {
      recent.splice(recent.indexOf(jku))
    }

    recent.unshift(jku)
    jwkSets[jku] = jwks

    while (recent.length > max) {
      let jku = recent.pop()
      delete jwkSets[jku]
    }

    return Promise.resolve(jwks)
  }

  /**
   * getJwkFromJwks
   *
   * @description
   * Gets a JWK from a JWKSet by `kid`. If a JWK is not found
   * in the JWKSet, such as may happen in the case of key rotation
   * events, request from the network.
   *
   * @param {JWKSet} jwks
   * @param {string} jku
   * @param {string} kid
   *
   * @return {Promise<JWK>}
   */
  getJwkFromJwks (jwks, jku, kid) {
    let jwk = jwks.find({ kid, key_ops: { $in: ['verify'] } })

    // success
    if (jwk) {
      return Promise.resolve(jwk)
    }

    // try again
    return Promise.resolve()
      .then(() => this.getJwksFromNetwork(null, jku))
      .then(jwks => this.cacheJwks(jwks, jku))
      .then(jwks => {
        let jwk = jwks.find({ kid, key_ops: { $in: ['verify'] } })

        if (!jwk) {
          throw new Error('JWK not found in JWK Set')
        }

        return jwk
      })
  }

}

/**
 * Export
 */
module.exports = JWKSetCache
