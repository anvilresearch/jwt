# NOTICE

We’re archiving Anvil Connect and all related packages. This code is entirely MIT Licensed. You’re free to do with it what you want. That said, we are recommending _**against**_ using it, due to the potential for security issues arising from unmaintained software. For more information, see the announcement at [anvil.io](https://anvil.io).

# JWT _(@trust/jwt)_

[![standard-readme compliant](https://img.shields.io/badge/readme%20style-standard-brightgreen.svg?style=flat-square)](https://github.com/RichardLitt/standard-readme)
[![Build Status](https://travis-ci.org/anvilresearch/jwt.svg?branch=master)](https://travis-ci.org/anvilresearch/jwt)
[![codecov](https://codecov.io/gh/anvilresearch/jwt/branch/master/graph/badge.svg)](https://codecov.io/gh/anvilresearch/jwt)

> JSON Web Token for JavaScript

TODO: Update this

> The JOSE suite of specifications standardizes various mechanisms required for
integrity protection and encryption of data structured and serialized as JSON.

This package implements [JWT][jwt], [JWD][jwd], [JWS][jws] and [JWE][jwe] for use in JavaScript applications.

Underlying cryptography is provided by [W3C Web Cryptography API][w3c-webcrypto],
available natively in browsers and [via npm][node-webcrypto] in Node.js.
Additionally, [JSON Schema][json-schema] is used for [object initialization and
validation][json-doc] with JWT and JWD.

[jwt]: https://tools.ietf.org/html/rfc7519
[jwd]: https://tools.ietf.org/html/draft-smith-oauth-json-web-document-00
[jws]: https://tools.ietf.org/html/rfc7515
[jwe]: https://tools.ietf.org/html/rfc7516
[jwa]: https://tools.ietf.org/html/rfc7518
[jwk]: https://tools.ietf.org/html/rfc7517
[jwkset]: https://tools.ietf.org/html/rfc7517#section-5
[w3c-webcrypto]: https://www.w3.org/TR/WebCryptoAPI/
[node-webcrypto]: https://www.npmjs.com/package/@trust/webcrypto
[json-schema]: http://json-schema.org/
[json-doc]: https://www.npmjs.com/package/@trust/json-document


## Table of Contents

* [Security](#security)
* [Install](#install)
* [Usage](#usage)
* [Develop](#develop)
* [API](#api)
  * [JWT](#jwt)
  * [JWD](#jwd)
* [Contribute](#contribute)
* [MIT License](#mit-license)

## Security

TBD

## Install

```bash
$ npm install @trust/jwt --save
```

## Usage

### Node.js

```
const { JWT, JWD } = require('@trust/jwt')
```

### Browser

TBD

## Develop

### Install

```bash
$ git clone git@github.com:anvilresearch/jwt.git
$ cd jwt
$ npm install
```

### Test

```bash
$ npm test        // Node.js
$ npm run karma   // Karma (browser)
```

## API

### JWT

#### new JWT()
#### (static) decode(token) → {JWT}
#### (static) encode(…data) → {Promise.&lt;SerializedToken&gt;}
#### (static) from(data) → {JWT}
#### (static) fromCompact(data) → {JWT}
#### (static) fromFlattened(data) → {JWT}
#### (static) fromGeneral(data) → {JWT}
#### (static) sign() → {Promise.&lt;SerializedToken&gt;}
#### (static) verify(…data) → {Promise.&lt;JWT&gt;}
#### encode(…data) → {Promise.&lt;SerializedToken&gt;}
#### isJWE()
#### resolveKeys()
#### serialize() → {SerializedToken}
#### sign(…data) → {Promise.&lt;SerializedToken&gt;}
#### toCompact()
#### toFlattened()
#### toGeneral()
#### toJWD() → {JWD}
#### verify(…data) → {Promise.&lt;(Boolean|Object)&gt;}

### JWD

JWD inherits from JWT.

#### new JWD()
#### (static) decode(token) → {JWD}
#### (static) fromDocumentFlattened(data) → {JWD}
#### (static) fromDocumentGeneral(data) → {JWD}
#### serialize() → {SerializedToken}
#### toDocumentFlattened()
#### toDocumentGeneral()
#### toJWT() → {JWT}

## Contribute

### Issues

* please file [issues](https://github.com/anvilresearch/jwt/issues) :)
* for bug reports, include relevant details such as platform, version, relevant data, and stack traces
* be sure to check for existing issues before opening new ones
* read the documentation before asking questions
* it's strongly recommended to open an issue before hacking and submitting a PR
* we reserve the right to close an issue for excessive bikeshedding

### Pull requests

#### Policy

* we're not presently accepting *unsolicited* pull requests
* create an issue to discuss proposed features before submitting a pull request
* create an issue to propose changes of code style or introduce new tooling
* ensure your work is harmonious with the overall direction of the project
* ensure your work does not duplicate existing effort
* keep the scope compact; avoid PRs with more than one feature or fix
* code review with maintainers is required before any merging of pull requests
* new code must respect the style guide and overall architecture of the project
* be prepared to defend your work

#### Style guide

* [Conventional Changelog](https://github.com/bcoe/conventional-changelog-standard/blob/master/convention.md)
* [EditorConfig](http://editorconfig.org)
* ES6
* Standard JavaScript
* jsdocs

#### Code reviews

* required before merging PRs
* reviewers SHOULD run the code under review

### Collaborating

#### Weekly project meeting

* Thursdays from 1:00 PM to 2:00 Eastern US time at [TBD]
* Join remotely with Google Hangouts

#### Pair programming

* Required for new contributors
* Work directly with one or more members of the core development team

### Code of conduct

* @trust/jwt follows the [Contributor Covenant](http://contributor-covenant.org/version/1/3/0/) Code of Conduct.

### Contributors

* Christian Smith [@christiansmith](https://github.com/christiansmith)
* Greg Linklater [@EternalDeiwos](https://github.com/EternalDeiwos)
* Dmitri Zagidulin [@dmitrizagidulin](https://github.com/dmitrizagidulin)
* Ioan Budea [@johnny90](https://github.com/johnny90)

## MIT License

Copyright (c) 2016 Anvil Research, Inc.
