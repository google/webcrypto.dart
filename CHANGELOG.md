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
