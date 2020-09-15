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
