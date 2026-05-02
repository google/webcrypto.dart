Cross-Platform Web Cryptography Implementation
=============================================
This package provides a cross-platform implementation of the
[Web Cryptography API][webcrypto-spec].

**Disclaimer:** This is not an officially supported Google product.

This packages provides an implementation of the
[Web Cryptography API][webcrypto-spec] across multiple platforms. Outside the
browser, this package features a native implementation embedding
[BoringSSL][boringssl-src] using [`dart:ffi`][dart-ffi]. When used inside a
web browser this package wraps the [`window.crypto`][window-crypto] APIs and
providing the same Dart API as the native implementation.

This way, `package:webcrypto` provides the same crypto API on **Android**, **iOS**, **Web**, **Windows**, **Linux** and **Mac**.

**Example**
```dart
import 'dart:convert' show base64, utf8;
import 'package:webcrypto/webcrypto.dart';

Future<void> main() async {
  final digest = await Hash.sha256.digestBytes(utf8.encode('Hello World'));
  print(base.encode(digest));
}
```

[![Coverage Status](https://coveralls.io/repos/github/google/webcrypto.dart/badge.svg?branch=master)](https://coveralls.io/github/google/webcrypto.dart?branch=master)

**Features:**
 * Get random bytes
 * Digest (sha-1/sha-256/sha-384/sha-512)
 * HMAC (sign/verify)
 * RSASSA-PKCS1-v1_5 (sign/verify)
 * RSA-PSS (sign/verify)
 * ECDSA (sign/verify)
 * RSA-OAEP	(encrypt/decrypt)
 * AES-CTR, AES-CBC, AES-GCM (encrypt/decrypt)
 * ECDH (deriveBits)
 * HKDF (deriveBits)
 * PBKDF2	(deriveBits)
 * BoringSSL, Chrome and Firefox implementations pass the same test cases.

**Missing:**
 * Exceptions and errors thrown for invalid input is not tested yet.
 * The native implementation executes on the main-thread, however, all expensive
   APIs are asynchronous, so they can be offloaded in the future.

For a discussion of the API design of this package,
see `doc/design-rationale-md`.


## System dependencies

When you have a dependency on `package:webcrypto`, it will use
[hooks](https://dart.dev/tools/hooks) to build BoringSSL. Thus, your system
must have:

 * `cmake`, and,
 * a C compiler (like `gcc` or `clang`)

## Limitations
This package has a few limitations compared to the
[Web Cryptography API][webcrypto-spec]. For a discussion of parity with
Web Cryptography APIs see `doc/webcrypto-parity.md`.

 * `deriveKey` is not supported, however, keys can always be created from
    `derivedBits` which is supported.
 * `wrapKey` is not supported, however, keys can be exported an encrypted.
 * `unwrapKey` is not supported, however, keys can be decrypted and imported.
 * `AES-KW` is not supported because it does not support `encrypt`/`decrypt`.

## Compatibility notes
This package has many tests cases to asses compatibility across the native
implementation using BoringSSL and various browser implementations of the
Web Cryptography APIs.

At the moment **compatibility testing is limited** to native implementation,
Chrome, Firefox and Safari.

**Known Issues:**
 * Chrome and BoringSSL does not support valid ECDH spki-formatted keys exported
   by Firefox prior to version 72.
 * Firefox does not support PKCS8 import/export for ECDSA and ECDH keys.
 * Firefox does not handle counter wrap around for `AES-CTR`.
 * Safari does not support P-521 for ECDSA and ECDH.
 * The browser implementation of streaming methods for _encryption_,
   _decryption_, _signing_ and _verification_ buffers the entire input, because
   `window.crypto` does not expose a streaming API. However, the native
   implementation using BoringSSL does support streaming.
 * In browsers, operations backed by `window.crypto.subtle` require a secure
   context. When loaded from an insecure context, `package:webcrypto` throws
   `UnsupportedError` for those operations with guidance to use HTTPS or a
   trustworthy local origin such as `localhost`. `fillRandomBytes()` continues
   to work because it uses `window.crypto.getRandomValues()`, which browsers
   expose outside secure contexts.

## References

 * [Web Cryptograpy Specification][webcrypto-spec].
 * [MDN Web Crypto API][webcrypto-mdn].
 * [Chromium Web Crypto Source][chrome-src].
 * [BoringSSL Source][boringssl-src].
 * [BoringSSL Documentation][boringssl-docs].


[window-crypto]: https://developer.mozilla.org/en-US/docs/Web/API/Window/crypto
[webcrypto-spec]: https://www.w3.org/TR/WebCryptoAPI/
[boringssl-src]: https://boringssl.googlesource.com/boringssl/
[boringssl-docs]: https://commondatastorage.googleapis.com/chromium-boringssl-docs/headers.html
[dart-ffi]: https://api.dart.dev/stable/2.8.4/dart-ffi/dart-ffi-library.html
[chrome-src]: https://chromium.googlesource.com/chromium/src/+/master/components/webcrypto
[webcrypto-mdn]: https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API
