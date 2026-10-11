# 0.6.2-wip
* Fixed incorrect RSA public exponents during native key generation on
  32-bit platforms.
* Fixed native AES-CTR processing of large stream chunks.
* Snapshot AES-CBC IVs, AES-CTR counters, and HMAC signatures before
  asynchronous processing so caller mutations do not change the operation.
* Fixed HMAC JWK imports with an explicit key length and rejected empty
  imported HMAC keys. Added support for generating HMAC keys larger than
  the browser random-fill limit.
* Fixed native ECDH and PBKDF2 derivation to support zero-length results.
* Reject oversized native HKDF output lengths before allocating memory,
  and reject overflowing PBKDF2 iteration counts and RSA-PSS salt lengths
  before passing them to native code.
* Validate browser ECDH output lengths, AES-GCM tag lengths, and RSA
  modulus lengths before browser interop. Validate AES and HMAC key
  generation lengths and supported typed-data inputs to `fillRandomBytes`.
* Fixed AES-CBC invalid-IV errors and delivered RSA-PSS byte-operation
  validation errors through the returned futures.
* Reject trailing bytes in imported EC and RSA keys, malformed JWK
  base64url values, private key material in native RSA public-key JWK
  imports, and unsupported multi-prime RSA JWKs.
* Fixed parsing of JSON-decoded RSA JWK `oth` entries and the RSA-OAEP
  SHA-1 JWK algorithm identifier. Align browser JWK export `use` metadata
  with native exports.
* Fixed JS exception handling for WebAssembly builds.
* Fixed stale native build-cache reuse after changes to CMake configuration
  or BoringSSL include files.
* Updated runtime dependencies to `hooks` 2.x and
  `native_toolchain_cmake` 0.3.x.
* Added documentation for `wrapKey` compatibility and clarified ECDH
  imports, derivation limits, and RSA-OAEP plaintext size limits.

# 0.6.1
* Added Dart native build hooks and native asset lookup for the bundled
  native library, enabling `dart test` for the core package.
* `webcrypto` is now packaged as a Dart package using native hooks instead of
  Flutter plugin scaffolding.
* Improved web error handling when `window.crypto.subtle` is unavailable in
  insecure contexts by throwing a clearer `UnsupportedError` with guidance.
* Fixed native AES-CTR encryption and decryption for inputs larger than the
  internal chunk buffer.
* Added documentation for performing `deriveKey` using `deriveBits` and
  `importRaw`.

# 0.6.0
* Replaced the `KeyPair` class with `typedef KeyPair<T, S> = ({T privateKey, S publicKey})` and refactored key generation methods to return a named record.
* Bumped minimum required CMake version to `3.10` for building the
  bundled native library (`flutter pub run webcrypto:setup`).

# 0.5.8
* All classes previously annotated `@sealed` are now `final`!
* Migrate from Gradle Imperative Apply to [Gradle Plugin DSL](https://docs.flutter.dev/release/breaking-changes/flutter-gradle-plugin-apply).
* Bumped Kotlin Version to 1.7.10.
* Removed the `GCC_WARN_INHIBIT_ALL_WARNINGS` option to ensure compatibitity with Xcode 16.
* Code coverage is now 89% as reported to [coveralls.io](https://coveralls.io/github/google/webcrypto.dart?branch=master)!
* Add support for compiling to WASM.

# 0.5.7
* Added compatibility for AGP 8.4.
* Improved API documentation for ECDH.
* Bumped minimum Android SDK/ API level to 21, dropping support for Android 4 and below.

# 0.5.6
* Disable LTO on Android to fix [#80](https://github.com/google/webcrypto.dart/issues/80).
* Migrate to `dart:js_interop` to ensure [wasm compatibility](https://dart.dev/interop/js-interop/package-web#package-web-vs-dart-html).

# 0.5.5
* Adds a namespace in `build.gradle` for compatibility with AGP 8.0.

# 0.5.4
* Added MacOS desktop support.
* Added Windows desktop support.
* Additional API documentation.
* Add `topics` to `pubspec.yaml`.
* Bumped lower bound SDK constraint to require Dart `>= 3.0.0`.

# 0.5.3
* Migrate to Flutter 3.0
* Added Linux desktop support.
* Fixed issues with `dart2js` in release mode.

# 0.5.2

* Migrates `dart:ffi`s generic `sizeOf` uses, which will be removed in Dart 2.13.

# 0.5.1
 * Uses `package:ffigen` to generate the Dart bindings.
 * Bumped SDK constraint to Dart 2.12.

# 0.5.0
 * Rolled forward all dependencies to Dart 2.12 previews.
 * Migrated breaking changes for [package:ffi](https://pub.dev/packages/ffi) version `1.0.0`.
 * Bumped SDK constraint to Dart 2.12 beta.

# 0.5.0-null-safety.0
 * Ported to null-safety without any breaking changes.

# 0.2.2
 * Increased Flutter SDK constraint to `>=1.24.0-10.2.pre` (current beta),
   because API version breakage in dynamic linking API for Dart SDK.
 * Additional documentation for `RsassaPkcs1V15PrivateKey` and
   `RsassaPkcs1V15PublicKey`.

# 0.2.1
 * Added finalizers for `ssl.EVP_PKEY` and running tests under `valgrind` unable
   to find any obvious memory leaks.
 * Increased Flutter SDK constraint to `>=1.22.0-12.1.pre` (current beta).

# 0.2.0
 * Added `ios` support.
 * Added `<2.0.0` upper-bound on Flutter SDK constraint.

# 0.1.2
 * Fixed sizeof `ssl.CBB` causing occasional segfaults, as we previously
   allocated too few bytes.
 * Ported `flutter pub run webcrypto:setup` to work on Mac when `cmake` is
   installed.

# 0.1.1
 * Removed unused code referencing `dart:cli`, causing analysis errors on
   [pub.dev](https://pub.dev/packages/webcrypto).
 * Added more API documentation for `AesCbcSecretKey`.

# 0.1.0
 * Initial release.
