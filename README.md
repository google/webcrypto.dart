Web Cryptography for Dart
=========================

This package aims to provide a useful cryptography package for Dart, by offering
a Dartified interface for the [Web Cryptograph API][webcrypto-spec] available
in modern browsers, and offer the same API when running on the VM/AOT.

The rationale for choice of Web Cryptography and guidelines driving the API
design is articulated in [doc/design-rationale.md](doc/design-rationale.md).
In short this package aims to follow the [Web Cryptograph Spec][webcrypto-spec]
while adding typing and accepting ugly names for the sake for future proofing.

For a quick outline see [API reference on X20][api-docs].

## Status
Implementation is complete using BoringSSL/`dart:ffi` on the VM and Web Crypto
in javascript.

**Completed**
 * Get random bytes
 * digest (sha-1/sha-256/sha-384/sha-512)
 * HMAC (sign/verify)
 * RSASSA-PKCS1-v1_5 (sign/verify)
 * RSA-PSS (sign/verify)
 * ECDSA (sign/verify)
 * RSA-OAEP	(encrypt/decrypt)
 * AES-CTR, AES-CBC, AES-GCM (encrypt/decrypt)
 * ECDH (deriveBits)
 * HKDF (deriveBits)
 * PBKDF2	(deriveBits)
 * BoringSSL, Chrome and Firefox implementation pass the same test cases.

**Missing**
 * Exceptions/errors thrown for invalid input may still differ between
   implementations, test cases have not been extended to cover invalid input.

## Limitations
 
 * `deriveKey` is not supported, keys can always be created from `derivedBits`
    which is supported.
 * `wrapKey` / `unwrapKey` is not supported, keys can be exported/encrypted or
    decrypted/imported.
 * `AES-KW` is not supported because it only supports `wrapKey` / `unwrapKey`
    but doesn't support `encrypt`/`decrypt`.

## Compatibility notes

 * Chrome and BoringSSL does not support valid ECDH spki-formatted keys exported
   by Firefox prior to version 72.
 * Firefox does not support pkcs8 import/export for ECDSA and ECDH keys.
 * Firefox does not handle counter wrap around for `AES-CTR`.

## References

 * [API Reference on X20][api-docs].
 * [Web Cryptograpy Specification][webcrypto-spec].
 * [MDN Web Crypto API][webcrypto-mdn].
 * [Chromium Web Crypto Source][chrome-src].
 * [BoringSSL Source][boringssl-src].
 * [BoringSSL Documentation][boringssl-docs].

[api-docs]: https://jonasfj.users.x20web.corp.google.com/www/no_crawl/webcrypto.dart/webcrypto/webcrypto-library.html
[webcrypto-spec]: https://www.w3.org/TR/WebCryptoAPI/
[webcrypto-mdn]: https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API
[chrome-src]: https://chromium.googlesource.com/chromium/src/+/master/components/webcrypto
[boringssl-src]: https://boringssl.googlesource.com/boringssl/
[boringssl-docs]: https://commondatastorage.googleapis.com/chromium-boringssl-docs/headers.html
