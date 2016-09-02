/**
 * Package dependencies
 */
const {Formats} = require('json-document')

/**
 * Format extensions
 */
Formats.register('StringOrURI', new RegExp())
Formats.register('NumericDate', new RegExp())
Formats.register('url', new RegExp())
Formats.register('base64', new RegExp())
Formats.register('base64url', new RegExp())
Formats.register('MediaType', new RegExp())
