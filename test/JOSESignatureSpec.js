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
const { JWKSet } = require('@trust/jwk')
const JOSESignature = require('../src/JOSESignature')
const JWKSetCache = require('../src/JWKSetCache')

/**
 * Tests
 * @ignore
 */
describe.only('JOSESignature', () => {

  /**
   * constructor
   */
  describe('constructor', () => {
    let cache, signature, joseSignature

    beforeEach(() => {
      cache = {}
      signature = 'fake'
      joseSignature = new JOSESignature({
        foo: 'bar',
        unprotectedHeader: { anything: 'goes' },
        protectedHeader: { alg: 'RS256' },
        signature,
        cache
      })
    })

    it('should ignore properties it does not understand', () => {
      joseSignature.foo.should.equal('bar')
      joseSignature.unprotectedHeader.anything.should.equal('goes')
    })

    it('should require integrity protected header', () => {
      expect(() => {
        new JOSESignature({
          foo: 'bar',
          unprotectedHeader: { anything: 'goes' },
          signature,
          cache
        })
      }).to.throw('JOSESignature must define protected header')
    })

    it('should not define empty unprotected header', () => {
      joseSignature = new JOSESignature({
        unprotectedHeader: undefined,
        protectedHeader: { alg: 'RS256' },
        signature,
        cache
      })

      joseSignature.should.not.have.property('unprotectedHeader')
    })

    it('should require signature', () => {
      expect(() => {
        new JOSESignature({
          foo: 'bar',
          unprotectedHeader: { anything: 'goes' },
          protectedHeader: { alg: 'RS256' },
          cache
        })
      }).to.throw('JOSESignature must define signature')
    })

    it('should require absence of signature with unsecured JWS', () => {
      expect(() => {
        new JOSESignature({
          protectedHeader: { alg: 'none' },
          signature: 'nope'
        })
      }).to.throw('Unsecured JWS must not include signature')
    })

    it('should require JWK Set cache', () => {
      expect(() => {
        new JOSESignature({
          foo: 'bar',
          unprotectedHeader: { anything: 'goes' },
          protectedHeader: { alg: 'RS256' },
          signature
        })
      }).to.throw('JOSESignature requires cache')
    })

    it('should not require JWK Set cache with unsecured JWS', () => {
      expect(() => {
        new JOSESignature({
          protectedHeader: { alg: 'none' }
        })
      }).to.not.throw()
    })

    it('should not enumerate cache property', () => {
      JSON.stringify(joseSignature).should.not.include('"cache":')
    })

    it('should not include falsy unprotected header', () => {
      joseSignature = new JOSESignature({
        unprotectedHeader: undefined,
        protectedHeader: { alg: 'none' }
      })

      expect(joseSignature).to.not.have.property('unprotectedHeader')
    })

    it('should freeze the instance', () => {
      expect(() => {
        joseSignature.x = 1
      }).to.throw('is not extensible')
    })
  })

  /**
   * sign
   */
  describe('sign (static)', () => {
    let jwk

    before(() => {
      return JWKSet.generateKeys('ES256').then(jwks => jwk = jwks.keys[0])
    })

    it('should reject with missing payload', () => {
      return JOSESignature.sign({})
        .should.be.rejectedWith('Missing payload for JOSE Signature')
    })

    it('should reject with missing JWK Set cache', () => {
      return JOSESignature.sign({ payload: {} })
        .should.be.rejectedWith('Missing JWKSetCache for JOSE Signature')
    })

    it('should reject with missing private key', () => {
      return JOSESignature.sign({ payload: {}, cache: {} })
        .should.be.rejectedWith('JOSE Signature requires JWK')
    })

    it('should resolve JOSESignature instance', () => {
      return JOSESignature.sign({
        payload: {},
        protectedHeaderParams: {
          kid: jwk.kid,
          jku: 'https://example.com/jwks'
        },
        cache: {},
        jwk
      }).should.eventually.be.instanceOf(JOSESignature)
    })

  })

  /**
   * verify
   */
  describe('verify with kid and jku', () => {
    let payload, joseSignature, jwks, jwk

    beforeEach(() => {
      return JWKSet.generateKeys('ES256').then(jwkSet => {
        jwks = jwkSet
        jwk = jwks.keys[1]
        payload = { hello: 'world' }

        return JOSESignature.sign({
          payload,
          protectedHeaderParams: {
            kid: jwk.kid,
            jku: 'https://example.com/jwks'
          },
          cache: new JWKSetCache(),
          jwk: jwks.keys[0]
        })
        .then(sig => joseSignature = sig)
      })
    })

    it('should reject with missing "alg" header parameter', () => {
      delete joseSignature.protectedHeader.alg
      return joseSignature.verify({ payload })
        .should.be.rejectedWith('Missing "alg" in protected header')
    })


    it('should resolve "true" with valid unsecured JWS', () => {
      joseSignature = new JOSESignature({
        protectedHeader: { alg: 'none' }
      })

      return joseSignature.verify(payload)
        .should.eventually.equal(true)
    })

    it('should resolve "true" with JWK and verifiable signature', () => {
      let intercept = nock('https://example.com')
        .get('/jwks')
        .reply(200, jwks)

      return joseSignature.verify(payload)
        .should.eventually.equal(true)
    })

    it('should resolve "false" with JWK and unverifiable signature', () => {
      let intercept = nock('https://example.com')
        .get('/jwks')
        .reply(200, jwks)

      return joseSignature.verify({ hello: 'wrong' })
        .should.eventually.equal(false)
    })
  })

})
