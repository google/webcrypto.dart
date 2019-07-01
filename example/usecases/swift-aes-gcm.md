AES-GCM authenicated encryption with cryptoswift
================================================

A common operation in everything from password managers to note taking
applications is encryption of data before storage in cloud systems. A popular
swift package offering cryptographic primitives for this is
[cryptoswift][cryptoswift]. The following is their example for how to use `AES`
in `GCM` mode:

```swift
do {
    // In combined mode, the authentication tag is directly appended to the encrypted message. This is usually what you want.
    let gcm = GCM(iv: iv, mode: .combined)
    let aes = try AES(key: key, blockMode: gcm, padding: .noPadding)
    let encrypted = try aes.encrypt(plaintext)
    let tag = gcm.authenticationTag
catch {
    // failed
}
```

This can also be done with `'dart:crypto'`, as illustrated in the following
sample (assumed to be using `draft4.dart`).

```dart
import 'dart:crypto';

// Create an IV with random bytes
final iv = Uint8Array(32);
getRandomBytes(iv);

final key = await AesGcmSecretKey.importKey(keyBytes);

final cipherTextAndTag = await key.encrypt(dataBytes, iv, tagLength: 128);

final cipherText = cipherTextAndTag.sublist(0, cipherTextAndTag.length - 128);
final tag = cipherTextAndTag.sublist(cipherTextAndTag.length - 128);
```

Web Crypto always appends the generated authentication tag to the cipher text.
We maintain this API because we do not have multiple return values, and presume
that this is generally a good idea.

[cryptoswift-gh]: https://github.com/krzyzanowskim/CryptoSwift
[cryptoswift]: https://cryptoswift.io/#aes-gcm
