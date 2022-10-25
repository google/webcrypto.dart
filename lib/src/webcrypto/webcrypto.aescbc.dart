// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

part of webcrypto;

/// AES secret key for symmetric encryption and decryption using AES in
/// _Cipher Block Chaining mode_ (CBC-mode), as described in
/// [NIST SP800-38A][1].
///
/// Encrypted messages are always padded in PKCS#7 mode, as described in
/// [RFC 2315 Section 10.3 step 2][2]. This padding is stripped when
/// the message is decrypted.
///
/// An [AesCbcSecretKey] can be imported from:
///  * Raw bytes using [AesCbcSecretKey.importRawKey], and,
///  * [JWK] format using [AesCbcSecretKey.importJsonWebKey].
///
/// A random [AesCbcSecretKey] can generated using
/// [AesCbcSecretKey.generateKey].
///
/// {@macro AesCbcSecretKey-encryptBytes/decryptBytes:example}
///
/// [1]: https://csrc.nist.gov/publications/detail/sp/800-38a/final
/// [2]: https://tools.ietf.org/html/rfc2315#section-10.3
/// [3]: https://tools.ietf.org/html/rfc7517
@sealed
abstract class AesCbcSecretKey {
  AesCbcSecretKey._(); // keep the constructor private.

  /// Import an [AesCbcSecretKey] from raw [keyData].
  ///
  /// [KeyData] must be either:
  ///  * 16 bytes (128 bit) for AES-128, or,
  ///  * 32 bytes (256 bit) for AES-256.
  ///
  /// {@template AES:no-support-for-AES-192}
  /// Support for AES-192 (24 byte keys) is intentionally omitted, in line with
  /// the [decision not support AES-192 in Chrome](https://crbug.com/533699).
  /// {@endtemplate}
  ///
  /// **Example**
  /// ```dart
  /// import 'dart:convert' show utf8;
  /// import 'dart:typed_data' show Uint8List;
  /// import 'package:webcrypto/webcrypto.dart';
  ///
  /// final rawKey = Uint8List(16);
  /// fillRandomBytes(rawKey);
  ///
  /// final k = await AesCbcSecretKey.importRawKey(rawKey);
  ///
  /// // Use a unique IV for each message.
  /// final iv = Uint8List(16);
  /// fillRandomBytes(iv);
  ///
  /// // Encrypt a message
  /// final c = await k.encryptBytes(utf8.encode('hello world'), iv);
  ///
  /// print(utf8.decode(await k.decryptBytes(c, iv))); // hello world
  /// ```
  static Future<AesCbcSecretKey> importRawKey(List<int> keyData) {
    return impl.aesCbc_importRawKey(keyData);
  }

  /// Import an [AesCbcSecretKey] from [JSON Web Key][1].
  ///
  /// JSON Web Keys imported using [AesCbcSecretKey.importJsonWebKey]
  /// must have `"kty": "oct"`, and the `"alg"` property of the imported [jwk]
  /// must be either:
  ///  * `"alg": "A128CBC"` for AES-128, or
  ///  * `"alg": "A256CBC"` for AES-256.
  ///
  /// {@macro AES:no-support-for-AES-192}
  ///
  /// If specified the `"use"` property of the imported [jwk] must be
  /// `"use": "sig"`.
  ///
  /// {@macro importJsonWebKey:throws-FormatException-if-jwk}
  ///
  /// **Example**
  /// ```dart
  /// import 'dart:convert' show jsonEncode, jsonDecode;
  /// import 'package:webcrypto/webcrypto.dart';
  ///
  /// // JSON Web Key as a string containing JSON.
  /// final jwk = '{"kty": "oct", "alg": "A256CBC", "k": ...}';
  ///
  /// // Import secret key from decoded JSON.
  /// final key = await AesCbcSecretKey.importJsonWebKey(jsonDecode(jwk));
  ///
  /// // Export the key (print it in same format as it was given).
  /// Map<String, dynamic> keyData = await key.exportJsonWebKey();
  /// print(jsonEncode(keyData));
  /// ```
  ///
  /// [1]: https://tools.ietf.org/html/rfc7517
  // TODO: Decide if we want restrictions on "use" property" (we probably have it on web, if we don't strip it)
  // TODO: Decide if we want place restrictions on key_ops
  static Future<AesCbcSecretKey> importJsonWebKey(Map<String, dynamic> jwk) {
    return impl.aesCbc_importJsonWebKey(jwk);
  }

  /// Generate random [AesCbcSecretKey].
  ///
  /// The [length] is given in bits, and implies the AES variant to be used.
  /// The [length] can be either:
  ///  * 128 for AES-128, or,
  ///  * 256 for AES-256.
  ///
  /// {@macro AES:no-support-for-AES-192}
  ///
  /// **Example**
  /// ```dart
  /// import 'package:webcrypto/webcrypto.dart';
  ///
  /// // Generate a new random HMAC secret key for AES-256.
  /// final key = await AesCbcSecretKey.generate(256);
  /// ```
  static Future<AesCbcSecretKey> generateKey(int length) {
    return impl.aesCbc_generateKey(length);
  }

  /// Encrypt [data] with this [AesCbcSecretKey] using AES in _Cipher Block
  /// Chaining_ mode, as specified in [NIST SP800-38A][1].
  ///
  /// {@template AesCbcSecretKey-encrypt:iv}
  /// The operation requires a 16 bytes _initalization vector_ [iv]. The [iv]
  /// needs not be secret, but it must be unpredictable. In particular, for a
  /// given plaintext it must not be possible to predict the [iv] that will be
  /// used to encrypt the plaintext.
  /// For detailed discussion of the initialization vector requirements for
  /// AES-CBC, see [Appendix C of NIST SP800-38A](https://csrc.nist.gov/publications/detail/sp/800-38a/final).
  /// {@endtemplate}
  ///
  /// {@template AesCbcSecretKey-encrypt:padding}
  /// Encrypted output is always padded in PKCS#7 mode, as described in
  /// [RFC 2315 Section 10.3 step 2](https://tools.ietf.org/html/rfc2315#section-10.3).
  /// This padding is stripped when the message is decrypted.
  /// {@endtemplate}
  ///
  /// {@template AesCbcSecretKey-encryptBytes/decryptBytes:example}
  /// **Example**
  /// ```dart
  /// import 'dart:convert' show utf8;
  /// import 'dart:typed_data' show Uint8List;
  /// import 'package:webcrypto/webcrypto.dart';
  ///
  /// // Generate a new random HMAC secret key for AES-256.
  /// final key = await AesCbcSecretKey.generate(256);
  ///
  /// // Use a unique IV for each message.
  /// final iv = Uint8List(16);
  /// fillRandomBytes(iv);
  ///
  /// // Encrypt a message
  /// final c = await k.encryptBytes(utf8.encode('hello world'), iv);
  ///
  /// // Decrypt message (requires the same iv)
  /// print(utf8.decode(await k.decryptBytes(c, iv))); // hello world
  /// ```
  /// {@endtemplate}
  ///
  /// [1]: https://csrc.nist.gov/publications/detail/sp/800-38a/final
  Future<Uint8List> encryptBytes(List<int> data, List<int> iv);

  /// Encrypt [data] with this [AesCbcSecretKey] using AES in _Cipher Block
  /// Chaining_ mode, as specified in [NIST SP800-38A][1].
  ///
  /// {@macro AesCbcSecretKey-encrypt:iv}
  ///
  /// {@macro AesCbcSecretKey-encrypt:padding}
  ///
  /// {@template AesCbcSecretKey-encryptStream/decryptStream:example}
  /// **Example**
  /// ```dart
  /// import 'dart:io' show File;
  /// import 'dart:convert' show utf8;
  /// import 'dart:typed_data' show Uint8List;
  /// import 'package:async/async.dart' show collectBytes;
  /// import 'package:webcrypto/webcrypto.dart';
  ///
  /// // Generate a new random HMAC secret key for AES-256.
  /// final key = await AesCbcSecretKey.generate(256);
  ///
  /// // Use a unique IV for each message.
  /// final iv = Uint8List(16);
  /// fillRandomBytes(iv);
  ///
  /// // Encrypt a message from file and write to file
  /// final inputFile = File('message.txt');
  /// final encryptedFile = File('encrypted-message.binary');
  /// final c = await k.encryptStream(
  ///   inputFile.openRead(),
  ///   iv,
  /// ).pipe(encryptedFile.openWrite());
  ///
  /// // Decrypt message (requires the same iv)
  /// final decryptedBytes = await collectBytes(k.decryptStream(
  ///   encryptedFile.openRead(),
  ///   iv, // same iv as used for encryption
  /// ));
  /// // decryptedBytes should be equal to contents of inputFile
  /// assert(utf8.decode(decryptedBytes) == inputFile.readAsStringSync());
  /// ```
  /// {@endtemplate}
  ///
  /// [1]: https://csrc.nist.gov/publications/detail/sp/800-38a/final
  Stream<Uint8List> encryptStream(Stream<List<int>> data, List<int> iv);

  /// Decrypt [data] with this [AesCbcSecretKey] using AES in _Cipher Block
  /// Chaining_ mode, as specified in [NIST SP800-38A][1].
  ///
  /// {@template AesCbcSecretKey-decrypt:iv}
  /// To decrypt [data] the same _initalization vector_ [iv] as was used for
  /// encryption must be specified. The [iv] must always be 16 bytes.
  /// See [encryptBytes] for further discussion of the initialization vector.
  /// {@endtemplate}
  ///
  /// {@template AesCbcSecretKey-decrypt:padding}
  /// The encrypted [data] is always assumed to be padded in PKCS#7 mode,
  /// as described in
  /// [RFC 2315 Section 10.3 step 2](https://tools.ietf.org/html/rfc2315#section-10.3).
  /// This padding is stripped from the decrypted return value.
  /// The [encryptBytes] and [encryptStream] methods always apply this padding.
  /// {@endtemplate}
  ///
  /// {@macro AesCbcSecretKey-encryptBytes/decryptBytes:example}
  ///
  /// [1]: https://csrc.nist.gov/publications/detail/sp/800-38a/final
  Future<Uint8List> decryptBytes(List<int> data, List<int> iv);

  /// Decrypt [data] with this [AesCbcSecretKey] using AES in _Cipher Block
  /// Chaining_ mode, as specified in [NIST SP800-38A][1].
  ///
  /// {@macro AesCbcSecretKey-decrypt:iv}
  ///
  /// {@macro AesCbcSecretKey-decrypt:padding}
  ///
  /// {@macro AesCbcSecretKey-encryptStream/decryptStream:example}
  ///
  /// [1]: https://csrc.nist.gov/publications/detail/sp/800-38a/final
  Stream<Uint8List> decryptStream(Stream<List<int>> data, List<int> iv);

  /// Export [AesCbcSecretKey] as raw bytes.
  ///
  /// This returns raw bytes making up the secret key.
  ///
  /// **Example**
  /// ```dart
  /// import 'package:webcrypto/webcrypto.dart';
  ///
  /// // Generate a new random AES-258 secret key.
  /// final key = await AesCbcSecretKey.generate(256);
  ///
  /// // Extract the secret key.
  /// final secretBytes = await key.exportRawKey();
  ///
  /// // Print the key as base64
  /// print(base64.encode(secretBytes));
  ///
  /// // If we wanted to we could import the key as follows:
  /// // key = await AesCbcSecretKey.importRawKey(secretBytes);
  /// ```
  Future<Uint8List> exportRawKey();

  /// Export [AesCbcSecretKey] as [JSON Web Key][1].
  ///
  /// {@macro exportJsonWebKey:returns}
  ///
  /// **Example**
  /// ```dart
  /// import 'package:webcrypto/webcrypto.dart';
  /// import 'dart:convert' show jsonEncode;
  ///
  /// // Generate a new random AES-258 secret key.
  /// final key = await AesCbcSecretKey.generate(256);
  ///
  /// // Export the secret key.
  /// final jwk = await key.exportJsonWebKey();
  ///
  /// // The Map returned by `exportJsonWebKey()` can be converted to JSON with
  /// // `jsonEncode` from `dart:convert`, this will print something like:
  /// // {"kty": "oct", "alg": "A256CBC", "k": ...}
  /// print(jsonEncode(jwk));
  /// ```
  ///
  /// [1]: https://tools.ietf.org/html/rfc7517
  Future<Map<String, dynamic>> exportJsonWebKey();
}
