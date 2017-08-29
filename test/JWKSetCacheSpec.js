'use strict'

/**
 * Test dependencies
 * @ignore
 */
const cwd = process.cwd()
const path = require('path')
const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')
const nock = require('nock')

/**
 * Assertions
 * @ignore
 */
chai.use(chaiAsPromised)
chai.should()
const expect = chai.expect

/**
 * Code Under Test
 * @ignore
 */
const JWKSetCache = require('../src/JWKSetCache')
const { JWKSet, JWK } = require('@trust/jwk')
const PouchDB = require('pouchdb')
PouchDB.plugin(require('pouchdb-adapter-memory'))

/**
 * Tests
 * @ignore
 */
describe('JWKSetCache', () => {
  let jwks

  before(() => {
    return JWKSet.generateKeys('ES256').then(result => jwks = result)
  })

  /**
   * constructor
   */
  describe('constructor', () => {
    let cache, store

    beforeEach(() => {
      cache = new JWKSetCache()
    })

    it('should initialize jwkSets', () => {
      cache.jwkSets.should.eql({})
    })

    it('should intialize recent', () => {
      cache.recent.should.eql([])
    })

    it('should initialize default store value', () => {
      expect(cache.store).to.equal(null)
    })

    it('should initialize default max', () => {
      cache.max.should.equal(100)
    })

    it('should initialize store from options', () => {
      store = {}
      cache = new JWKSetCache({ store })
      cache.store.should.equal(store)
    })

    it('should initialize max from options', () => {
      cache = new JWKSetCache({ max: 100 })
      cache.max.should.equal(100)
    })
  })

  /**
   * getJwk
   */
  describe('getJwk', () => {
    let cache, store, jku

    beforeEach(() => {
      cache = new JWKSetCache()
      jku = 'https://example.com/jwks'
    })

    it('should reject with invalid kid', () => {
      let intercept = nock('https://example.com')
        .get('/jwks')
        .reply(200, jwks)
        .get('/jwks')
        .reply(200, jwks)

      return cache.getJwk(jwks, jku, 'unknown')
        .should.be.rejectedWith('JWK not found in JWK Set')
    })

    it('should reject with invalid jku', () => {
      let intercept = nock('https://example.com')
        .get('/unknown')
        .reply(404, 'Not found')

      return cache.getJwk(jwks, 'https://example.com/unknown', 'oughtabeok')
        .should.be.rejectedWith('JWK Set not found')
    })
  })

  describe('getJwks', () => {
    let cache, store, jku

    beforeEach(() => {
      cache = new JWKSetCache()
      jku = 'https://example.com/jwks'

      cache.jwkSets[jku] = jwks
      cache.recent = [jku]
    })

    it('should resolve a JWKSet', () => {
      return cache.getJwks(jku)
        .should.eventually.be.instanceOf(JWKSet)
    })

    it('should reject if not found', () => {
      let intercept = nock('https://example.com')
        .get('/unknown')
        .reply(404, 'Not found')

      return cache.getJwks('https://example.com/unknown')
        .should.be.rejectedWith('JWK Set not found')
    })
  })

  /**
   * getJwksFromCache
   */
  describe('getJwksFromCache', () => {
    let cache, jku

    before(() => {
      cache = new JWKSetCache()
      jku = 'https://example.com/jwks'

      cache.jwkSets[jku] = jwks
      cache.recent = [jku]
    })

    it('should resolve cached JWK Set', () => {
      return cache.getJwksFromCache(jku)
        .should.eventually.equal(jwks)
    })

    it('should resolve null if uncached', () => {
      return cache.getJwksFromCache('https://unknown.com/jwks')
        .should.eventually.equal(null)
    })
  })

  describe('getJwksFromStore', () => {
    let cache, store, jku

    beforeEach(() => {
      store = new PouchDB('jwks', { adapter: 'memory' })
      cache = new JWKSetCache({ store })
      jku = 'https://example.com/jwks'

      return store.post(Object.assign({ _id: jku }, jwks))
    })

    afterEach(() => {
      return store.destroy()
    })

    it('should resolve with provided JWK Set', () => {
      return cache.getJwksFromStore(jwks, jku)
        .should.eventually.equal(jwks)
    })

    it('should import JWK Set from data store', () => {
      return cache.getJwksFromStore(null, jku)
        .then(imported => {
          imported.should.be.instanceOf(JWKSet)
          expect(typeof imported['_id']).to.equal('string')
          expect(typeof imported['_rev']).to.equal('string')
          imported.keys.should.eql(jwks.keys)
        })
    })

    it('should resolve null if JWK Set is not found', () => {
      return cache.getJwksFromStore(null, 'https://unknown.com/jwks')
        .should.eventually.equal(null)
    })
  })

  describe('getJwksFromNetwork', () => {
    let cache, store, jku

    beforeEach(() => {
      store = new PouchDB('jwks', { adapter: 'memory' })
      cache = new JWKSetCache({ store })
      jku = 'https://example.com/jwks'
    })

    afterEach(() => {
      return store.destroy()
    })

    it('should resolve with provided JWK Set', () => {
      return cache.getJwksFromNetwork(jwks, jku)
        .should.eventually.equal(jwks)
    })

    it('should import JWK Set from jku', () => {
      let intercept = nock('https://example.com')
        .get('/jwks')
        .reply(200, jwks)

      return cache.getJwksFromNetwork(null, jku)
        .should.eventually.eql(jwks)
    })

    it('should store imported JWK Set', () => {
      let intercept = nock('https://example.com')
        .get('/jwks')
        .reply(200, jwks)

      return cache.getJwksFromNetwork(null, jku)
        .then(jwks => store.get(jku))
        .then(data => data.keys.should.eql(jwks.keys))
    })

    it('should resolve imported JWK Set', () => {
      let intercept = nock('https://example.com')
        .get('/jwks')
        .reply(200, jwks)

      return cache.getJwksFromNetwork(null, jku)
        .then(jwks => jwks.should.be.instanceOf(JWKSet))
    })

    it('should resolve null if JWK Set is not found', () => {
      let intercept = nock('https://example.com')
        .get('/jwks')
        .reply(404, 'Not found')

      return cache.getJwksFromNetwork(null, jku)
        .should.eventually.equal(null)
    })
  })

  /**
   * cacheJwks
   */
  describe('cacheJwks', () => {
    let cache, store, jku

    beforeEach(() => {
      cache = new JWKSetCache()
      jku = 'https://example.com/jwks'
    })

    it('should reject without jwks', () => {
      return cache.cacheJwks(null, jku)
        .should.be.rejectedWith('JWK Set not found')
    })

    it('should set new value to most recently used', () => {
      cache.recent = ['https://other.com/jwks']
      return cache.cacheJwks(jwks, jku)
        .then(jwks => {
          cache.jwkSets[jku].should.equal(jwks)
          cache.recent[0].should.equal(jku)
        })
    })

    it('should set existing value to most recently used', () => {
      cache.recent = ['https://other.com/jwks', jku]
      return cache.cacheJwks(jwks, jku)
        .then(jwks => {
          cache.jwkSets[jku].should.equal(jwks)
          cache.recent[0].should.equal(jku)
        })
    })

    it('should remove least recently used items greater than maximum', () => {
      cache.max = 2

      cache.jwkSets = {
        'https://other.com/jwks': {},
        'https://delete.me/jwks': {}
      }

      cache.recent = [
        'https://other.com/jwks',
        'https://delete.me/jwks'
      ]

      return cache.cacheJwks(jwks, jku)
        .then(jwks => {
          cache.recent.includes(0).should.equal(false)
          expect(cache.jwkSets['https://delete.me/jwks'])
            .to.equal(undefined)
        })
    })

    it('should eventually resolve a JWKSet', () => {
      return cache.cacheJwks(jwks, jku)
        .should.eventually.equal(jwks)
    })
  })

  /**
   * getJwkFromJwks
   */
  describe('getJwkFromJwks', () => {
    let cache, store, jku, jwk

    beforeEach(() => {
      store = new PouchDB('jwks', { adapter: 'memory' })
      cache = new JWKSetCache({ store })
      jku = 'https://example.com/jwks'
      jwk = jwks.find({ key_ops: { $in: ['verify'] } })

      return store.post(Object.assign({ _id: jku }, jwks))
    })

    afterEach(() => {
      return store.destroy()
    })

    it('should resolve JWK', () => {
      return cache.getJwkFromJwks(jwks, jku, jwk.kid)
        .should.eventually.equal(jwk)
    })

    it('should handle key rotation')

    it('should reject with JWK not found in JWK Set', () => {
      let intercept = nock('https://example.com')
        .get('/jwks')
        .reply(200, jwks)

      return cache.getJwkFromJwks(jwks, jku, 'unknown')
        .should.be.rejectedWith('JWK not found in JWK Set')
    })
  })

})
