Cross-Platform Web Cryptography Implemenation
=============================================

This package provides a cross-platform implementation of the
[Web Cryptograph API][webcrypto-spec]. In browsers this package wraps the
[`window.crypto`][window-crypto] APIs and provides an easy to use Dart API.
On other platforms, the same API, is implemented by interfacing
[BoringSSL][boringssl-src] using [`dart:ffi`][dart-ffi]. This way,
`package:webcrypto` provides the same crypto API on multiple platforms.

**Example**
```dart
import 'dart:convert' show base64, utf8;
import 'package:webcrypto/webcrypto.dart';

Future<void> main() async {
  final digest = await Hash.sha256.digestBytes(utf8.encode('Hello World'));
  print(base.encode(digest));
}
```

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
 * Finalizers not implemented yet, hence, memory leaks of keys is a known
   issues in the native implementation.
 * The native implementation executes on the main-thread, however, all expensive
   APIs are asynchronous, so they can be offloaded in the future.

For a discussion of the API design of this package,
see `doc/design-rationale-md`.

## Limitations
This package has a few limitations compared to the
Web Cryptograph API][webcrypto-spec]. For a discussion of parity with
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
Chrome and Firefox.

**Known Issues:**
 * Chrome and BoringSSL does not support valid ECDH spki-formatted keys exported
   by Firefox prior to version 72.
 * Firefox does not support PKCS8 import/export for ECDSA and ECDH keys.
 * Firefox does not handle counter wrap around for `AES-CTR`.
 * The browser implementation of streaming methods for _encryption_,
   _decryption_, _signing_ and _verification_ buffers the entire input, because
   `window.crypto` does not expose a streaming API. However, the native
   implementation using BoringSSL does support streaming.

## References

 * [Web Cryptograpy Specification][webcrypto-spec].
 * [MDN Web Crypto API][webcrypto-mdn].
 * [Chromium Web Crypto Source][chrome-src].
 * [BoringSSL Source][boringssl-src].
 * [BoringSSL Documentation][boringssl-docs].


[window-crypto]: webcrypto-mdn
[webcrypto-spec]: https://www.w3.org/TR/WebCryptoAPI/
[boringssl-src]: https://boringssl.googlesource.com/boringssl/
[boringssl-docs]: https://commondatastorage.googleapis.com/chromium-boringssl-docs/headers.html
[dart-ffi]: https://api.dart.dev/stable/2.8.4/dart-ffi/dart-ffi-library.html
[chrome-src]: https://chromium.googlesource.com/chromium/src/+/master/components/webcrypto
[webcrypto-mdn]: https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API
