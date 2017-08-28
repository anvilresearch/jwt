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
//const PouchDB = require('pouchdb')
//PouchDB.plugin(require('pouchdb-adapter-memory'))

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
    let lru

    beforeEach(() => {
      lru = new JWKSetCache()
    })

    it('should initialize cache', () => {
      lru.cache.should.be.instanceOf(Map)
    })

    it('should initialize default store', () => {
      lru.store.should.be.instanceOf(PouchDB)
    })

    it('should initialize default max', () => {
      lru.max.should.equal(25)
    })

    it('should initialize store from options', () => {
      lru = new JWKSetCache({ store: new PouchDB('fake', { adapter: 'memory' }) })
      lru.store.name.should.equal('fake')
    })

    it('should initialize max from options', () => {
      lru = new JWKSetCache({ max: 100 })
      lru.max.should.equal(100)
    })
  })

  describe('getJwk', () => {
    let lru, store, jku

    beforeEach(() => {
      store = new PouchDB('jwks', { adapter: 'memory' })
      lru = new JWKSetCache({ store })
      jku = 'https://example.com/jwks'

      return store.post(Object.assign({ _id: jku }, jwks))
    })

    afterEach(() => {
      return store.destroy()
    })

    it('should reject with invalid kid', () => {
      let intercept = nock('https://example.com')
        .get('/jwks')
        .reply(200, jwks)

      return lru.getJwk(jwks, jku, 'unknown')
        .should.be.rejectedWith('JWK not found in JWK Set')
    })

    it('should reject with invalid jku', () => {
      let intercept = nock('https://example.com')
        .get('/unknown')
        .reply(404, 'Not found')

      return lru.getJwk(jwks, 'https://example.com/unknown', 'oughtabeok')
        .should.be.rejectedWith('JWK Set not found')
    })
  })

  describe('getJwks', () => {
    let lru, store, jku

    beforeEach(() => {
      store = new PouchDB('jwks', { adapter: 'memory' })
      lru = new JWKSetCache({ store })
      jku = 'https://example.com/jwks'

      //lru.cache.set(jku, jwks)
      return store.post(Object.assign({ _id: jku }, jwks))
    })

    afterEach(() => {
      return store.destroy()
    })

    it('should resolve a JWKSet', () => {
      return lru.getJwks(jku)
        .should.eventually.be.instanceOf(JWKSet)
    })

    it('should reject if not found', () => {
      let intercept = nock('https://example.com')
        .get('/unknown')
        .reply(404, 'Not found')

      return lru.getJwks('https://example.com/unknown')
        .should.be.rejectedWith('JWK Set not found')
    })
  })

  /**
   * getJwksFromCache
   */
  describe('getJwksFromCache', () => {
    let lru

    before(() => {
      lru = new JWKSetCache()
      lru.cache.set('https://example.com/jwks', jwks)
    })

    it('should resolve cached JWK Set', () => {
      return lru.getJwksFromCache('https://example.com/jwks')
        .should.eventually.equal(jwks)
    })

    it('should resolve null if uncached', () => {
      return lru.getJwksFromCache('https://unknown.com/jwks')
        .should.eventually.equal(null)
    })
  })

  describe('getJwksFromStore', () => {
    let lru, store, jku

    beforeEach(() => {
      store = new PouchDB('jwks', { adapter: 'memory' })
      lru = new JWKSetCache({ store })
      jku = 'https://example.com/jwks'

      return store.post(Object.assign({ _id: jku }, jwks))
    })

    afterEach(() => {
      return store.destroy()
    })

    it('should resolve with provided JWK Set', () => {
      return lru.getJwksFromStore(jwks, jku)
        .should.eventually.equal(jwks)
    })

    it('should import JWK Set from data store', () => {
      return lru.getJwksFromStore(null, jku)
        .then(imported => {
          imported.should.be.instanceOf(JWKSet)
          expect(typeof imported['_id']).to.equal('string')
          expect(typeof imported['_rev']).to.equal('string')
          imported.keys.should.eql(jwks.keys)
        })
    })

    it('should resolve null if JWK Set is not found', () => {
      return lru.getJwksFromStore(null, 'https://unknown.com/jwks')
        .should.eventually.equal(null)
    })
  })

  describe('getJwksFromNetwork', () => {
    let lru, store, jku

    beforeEach(() => {
      store = new PouchDB('jwks', { adapter: 'memory' })
      lru = new JWKSetCache({ store })
      jku = 'https://example.com/jwks'
    })

    afterEach(() => {
      return store.destroy()
    })

    it('should resolve with provided JWK Set', () => {
      return lru.getJwksFromNetwork(jwks, jku)
        .should.eventually.equal(jwks)
    })

    it('should import JWK Set from jku', () => {
      let intercept = nock('https://example.com')
        .get('/jwks')
        .reply(200, jwks)

      return lru.getJwksFromNetwork(null, jku)
        .should.eventually.eql(jwks)
    })

    it('should store imported JWK Set', () => {
      let intercept = nock('https://example.com')
        .get('/jwks')
        .reply(200, jwks)

      return lru.getJwksFromNetwork(null, jku)
        .then(jwks => store.get(jku))
        .then(data => data.keys.should.eql(jwks.keys))
    })

    it('should resolve imported JWK Set', () => {
      let intercept = nock('https://example.com')
        .get('/jwks')
        .reply(200, jwks)

      return lru.getJwksFromNetwork(null, jku)
        .then(jwks => jwks.should.be.instanceOf(JWKSet))
    })

    it('should resolve null if JWK Set is not found', () => {
      let intercept = nock('https://example.com')
        .get('/jwks')
        .reply(404, 'Not found')

      return lru.getJwksFromNetwork(null, jku)
        .should.eventually.equal(null)
    })
  })

  /**
   * cacheJwks
   */
  describe('cacheJwks', () => {
    let lru, store, jku

    beforeEach(() => {
      store = new PouchDB('jwks', { adapter: 'memory' })
      lru = new JWKSetCache({ store })
      jku = 'https://example.com/jwks'
    })

    afterEach(() => {
      return store.destroy()
    })

    it('should reject without jwks', () => {
      return lru.cacheJwks(null, jku)
        .should.be.rejectedWith('JWK Set not found')
    })

    it('should set new value to most recently used')
    it('should set existing value to most recently used')
    it('should remove least recently used items greater than maximum')

    it('should eventually resolve a JWKSet', () => {
      return lru.cacheJwks(jwks, jku)
        .should.eventually.equal(jwks)
    })
  })

  /**
   * getJwkFromJwks
   */
  describe('getJwkFromJwks', () => {
    let lru, store, jku, jwk

    beforeEach(() => {
      store = new PouchDB('jwks', { adapter: 'memory' })
      lru = new JWKSetCache({ store })
      jku = 'https://example.com/jwks'
      jwk = jwks.find({ key_ops: { $in: ['verify'] } })

      return store.post(Object.assign({ _id: jku }, jwks))
    })

    afterEach(() => {
      return store.destroy()
    })

    it('should resolve JWK', () => {
      return lru.getJwkFromJwks(jwks, jku, jwk.kid)
        .should.eventually.equal(jwk)
    })

    it('should handle key rotation')

    it('should reject with JWK not found in JWK Set', () => {
      let intercept = nock('https://example.com')
        .get('/jwks')
        .reply(200, jwks)

      return lru.getJwkFromJwks(jwks, jku, 'unknown')
        .should.be.rejectedWith('JWK not found in JWK Set')
    })
  })

})
