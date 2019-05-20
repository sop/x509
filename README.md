# X.509

[![Build Status](https://travis-ci.org/sop/x509.svg?branch=php70)](https://travis-ci.org/sop/x509)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/sop/x509/badges/quality-score.png?b=php70)](https://scrutinizer-ci.com/g/sop/x509/?branch=php70)
[![Coverage Status](https://coveralls.io/repos/github/sop/x509/badge.svg?branch=php70)](https://coveralls.io/github/sop/x509?branch=php70)
[![License](https://poser.pugx.org/sop/x509/license)](https://github.com/sop/x509/blob/php70/LICENSE)

A PHP library for X.509 public key certificates, attribute certificates,
certification requests and certification path validation.

## Introduction

This library provides a pure PHP implementation of X.509 certificates.
The class hierarchy adapts to the ASN.1 types, which makes it easy to use
corresponding RFC's as a reference documentation.

## Features

- X.509 certificates ([RFC 5280](https://tools.ietf.org/html/rfc5280))
  - Certificate decoding and encoding
  - Certificate signing
- Certification requests ([PKCS #10](https://tools.ietf.org/html/rfc2986))
  - CSR decoding and encoding
- Certification path
  - Path building
  - Path validation
- Attribute certificates ([RFC 5755](https://tools.ietf.org/html/rfc5755))
  - AC decoding and encoding
  - AC signing

## Requirements

- PHP >=7.0
- gmp
- [sop/asn1](https://github.com/sop/asn1)
- [sop/x501](https://github.com/sop/x501)
- [sop/crypto-types](https://github.com/sop/crypto-types)
- [sop/crypto-bridge](https://github.com/sop/crypto-bridge)
- [sop/crypto-encoding](https://github.com/sop/crypto-encoding)

## Installation

This library is available on
[Packagist](https://packagist.org/packages/sop/x509).

    composer require sop/x509

## Code examples

Examples are located in
[`/examples`](https://github.com/sop/x509/tree/php70/examples)
directory.

- [Create a CA certificate](https://github.com/sop/x509/blob/php70/examples/create-ca-cert.php)
- [Create a CSR](https://github.com/sop/x509/blob/php70/examples/create-csr.php)
- [Issue a certificate](https://github.com/sop/x509/blob/php70/examples/issue-cert.php)
- [Validate a certification path](https://github.com/sop/x509/blob/php70/examples/path-validate.php)

## License

This project is licensed under the MIT License.
