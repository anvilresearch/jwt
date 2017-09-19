'use strict'

/**
 * Test dependencies
 */
const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')

/**
 * Assertions
 */
chai.use(chaiAsPromised)
chai.should()
let expect = chai.expect

/**
 * Code under test
 */
const crypto = require('@trust/webcrypto')
const { JWD } = require('../../src')
const JWTSchema = require('../../src/schemas/JWTSchema')
const { RsaPrivateJwk, RsaPublicJwk } = require('../keys')

/**
 * Test data
 */
const doc = {
  payload: {
    iss: "hello world!"
  },
  signatures: [
    {
      protected: {
        alg: "RS256",
        kid: "H3tKYTdpSy9Yle51Ap5HbDIhIudmVvsYgrn72_KjBFM",
        typ: "JWS",
        jku: "...",
      },
      signature: "P3gbGTMyQBSeMrZ4q3-MyECdrdehavN_YTQZCh7UpjLJjgI-Ecn7XZG64qtylanlCef64MRqVFrBrd0wLzuP1AXeqnZm--tP7ZREmhPNABHSupoiu6qdGbKQWTicwGZYjLFko7d9pOV8kQBITRB3XQHZ2j8Q_mA-gz3s12oHxJlPtONLwJHzSVyzIppQijL32JMjL7FwiXD_1kzGtVkMy_g9avzvoRvOwSAOCicFhLBWEZIs-pblaoCTp2k11PDAMcfi9s4GHpGTbeuFENI5tBu1jwYyXhQkbEsQJJ5KWTw3YbU0uPFXcw5CmmGOo8Ns_NIc0kXy79tfm7WhUAmh4A"
    }
  ]
}
const { payload, signatures: [ signatureDescriptor ] } = doc
const { protected: protectedHeader, signature } = signatureDescriptor
const serializedToken = JSON.stringify(doc)

/**
 * Tests
 */
describe('JWD', () => {

  /**
   * schema
   */
  describe('schema', () => {
    it('should return JWTSchema', () => {
      JWD.schema.should.equal(JWTSchema)
    })
  })

  /**
   * static decode
   */
  describe('static decode', () => {
    describe('non-string argument', () => {
      it('should throw with a DataError', () => {
        expect(() => {
          JWD.decode(false)
        }).to.throw('Invalid JWD')
      })
    })

    describe('Document Serialization', () => {
      it('should throw with a DataError', () => {
        expect(() => {
          JWD.decode('wrong')
        }).to.throw('Malformed JWD')
      })

      it('should return a JWD instance', () => {
        JWD.decode(serializedToken)
          .should.be.instanceof(JWD)
      })

      it('should set JWD type', () => {
        JWD.decode(serializedToken).should.have.property('type')
          .that.equals('JWS')
      })

      it('should set JWD payload', () => {
        JWD.decode(serializedToken)
          .should.deep.have.property('payload')
          .that.equals(payload)
      })

      it('should set JWD serialization', () => {
        JWD.decode(serializedToken)
          .should.deep.have.property('serialization')
          .that.equals('document')
      })

      it('should set JWD signatures', () => {
        JWD.decode(serializedToken)
          .should.have.property('signatures')
          .that.deep.includes(signatureDescriptor)
      })

      describe('signatures', () => {

        it('should set JWD protected header', () => {
          JWD.decode(serializedToken).signatures[0]
            .should.have.property('protected')
            .that.deep.equals(protectedHeader)
        })

        it('should set JWD signature', () => {
          JWD.decode(serializedToken).signatures[0]
            .should.have.property('signature')
            .that.deep.equals(signature)
        })
      })
    })
  })

  describe('static encode', () => {})
  describe('static sign', () => {})
  describe('static verify', () => {})

  describe('isJWE', () => {
    it('should return true with "recipients" field')
  })

  /**
   * resolveKeys
   */
  describe('resolveKeys', () => {
    it('should throw with invalid argument')
    it('should return true with match')
    it('should return false with no match')
    it('should match JWK by `kid`')
    it('should match JWK by `use`')
  })

  /**
   * encode
   */
  describe('encode', () => {
    it('should reject invalid JWD', (done) => {
      let jwd = new JWD({
        header: { alg: 'RS256', kid: 'r4nd0mbyt3s' },
        payload: { iss: null },
        jwk: RsaPrivateJwk
      })

      jwd.encode().should.be.rejected.and.notify(done)
    })

    it('should resolve a stringified JWD', (done) => {
      JWD.encode({
        payload: { iss: 'hello world!' },
        protected: { alg: 'RS256', typ: 'JWS', jku: '...' },
        jwk: RsaPrivateJwk,
      }).should.eventually.equal(serializedToken).and.notify(done)
    })
  })

  /**
   * verify
   */
  describe('verify', () => {
    it('should reject invalid JWD', (done) => {
      JWD.verify({ jwk: RsaPublicJwk, serialized: 'invalid' })
        .should.be.rejectedWith('Malformed JWD')
        .and.notify(done)
    })

    it('should resolve a boolean by default', (done) => {
      JWD.verify({ jwk: RsaPublicJwk, serialized: serializedToken })
        .should.eventually.equal(true).and.notify(done)
    })

    it('can resolve an instance', (done) => {
      JWD.verify({ jwk: RsaPublicJwk, serialized: serializedToken, result: 'instance' })
        .should.eventually.be.an.instanceOf(JWD).and.notify(done)
    })

    it.skip('can accept a string', (done) => {
      JWD.verify(serializedToken).should.eventually.equal(true).and.notify(done)
    })
  })
})
