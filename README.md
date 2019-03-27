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

Currently the code only works on Linux and Chrome, the `dart:ffi` implementation
requires Dart SDK from master branch. Library loading still relies on hardcoded
paths, which prevents publication on pub.

**Completed**
 * Get random bytes
 * digest (sha-1/sha-256/sha-384/sha-512)
   * Has bugs in Firefox (to be investigated)
   * Only import/export from raw key, JSON Web Key is not supported yet.
 * HMAC (sign/verify)
 * RSASSA-PKCS1-v1_5 (sign/verify)
   * Only import/export from pkcs8/spki, JSON Web Key is not supported yet.

**Missing**
 * RSA-PSS (sign/verify)
 * ECDSA (sign/verify)
 * RSA-OAEP	(encrypt/decrypt/wrapKey/unwrapKey)
 * AES-CTR, AES-CBC, AES-GCM (encrypt/decrypt/wrapKey/unwrapKey)
 * AES-KW (wrapKey/unwrapKey)
 * ECDH (deriveBits/deriveKey)
 * HKDF (deriveBits/deriveKey)
 * PBKDF2	(deriveBits/deriveKey)

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