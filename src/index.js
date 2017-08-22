/**
 * @module JSON Object Signing and Encryption (JOSE)
 */
const Formats = require('./formats')
const JWT = require('./jose/JWT')
const JWD = require('./jose/JWD')
const Base64URLSchema = require('./schemas/Base64URLSchema')
const JOSEHeaderSchema = require('./schemas/JOSEHeaderSchema')
const JWTClaimsSetSchema = require('./schemas/JWTClaimsSetSchema')
const JWTSchema = require('./schemas/JWTSchema')


/**
 * Export
 */
module.exports = {
  JWT,
  JWD,
  Base64URLSchema,
  JOSEHeaderSchema,
  JWTClaimsSetSchema,
  JWTSchema
}
