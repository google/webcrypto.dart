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

part of 'webcrypto.dart';

/// AES secret key for symmetric encryption and decryption using AES in
/// _Counter mode_ (CTR-mode), as described in [NIST SP800-38A][1].
///
/// An [AesCtrSecretKey] can be imported from:
///  * Raw bytes using [AesCtrSecretKey.importRawKey], and,
///  * [JWK][2] format using [AesCtrSecretKey.importJsonWebKey].
///
/// A random [AesCtrSecretKey] can be generated using
/// [AesCtrSecretKey.generateKey].
///
/// {@macro AesCtrSecretKey-encryptBytes/decryptBytes:example}
///
/// [1]: https://csrc.nist.gov/publications/detail/sp/800-38a/final
/// [2]: https://www.rfc-editor.org//rfc7517
final class AesCtrSecretKey {
  final AesCtrSecretKeyImpl _impl;

  AesCtrSecretKey._(this._impl); // keep the constructor private.

  /// Import an [AesCtrSecretKey] from raw [keyData].
  ///
  /// [KeyData] must be either:
  ///  * 16 bytes (128 bit) for AES-128, or,
  ///  * 32 bytes (256 bit) for AES-256.
  ///
  /// {@macro AES:no-support-for-AES-192}
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
  /// // Import key from raw bytes
  /// final k = await AesCtrSecretKey.importRawKey(rawKey);
  ///
  /// // Use a unique counter for each message.
  /// final ctr = Uint8List(16); // always 16 bytes
  /// fillRandomBytes(ctr);
  ///
  /// // Length of the counter, the N'th right most bits of ctr are incremented
  /// // for each block, the left most 128 - N bits are used as static nonce.
  /// final N = 64;
  ///
  /// // Encrypt a message
  /// final c = await k.encryptBytes(utf8.encode('hello world'), ctr, N);
  ///
  /// // Decrypt message (requires the same counter ctr and length N)
  /// print(utf8.decode(await k.decryptBytes(c, ctr, N))); // hello world
  /// ```
  static Future<AesCtrSecretKey> importRawKey(List<int> keyData) async {
    final impl = await webCryptImpl.aesCtrSecretKey.importRawKey(keyData);
    return AesCtrSecretKey._(impl);
  }

  /// Import an [AesCtrSecretKey] from [JSON Web Key][1].
  ///
  /// JSON Web Keys imported using [AesCtrSecretKey.importJsonWebKey]
  /// must have `"kty": "oct"`, and the `"alg"` property of the imported [jwk]
  /// must be either:
  ///  * `"alg": "A128CTR"` for AES-128, or
  ///  * `"alg": "A256CTR"` for AES-256.
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
  /// final jwk = '{"kty": "oct", "alg": "A256CTR", "k": ...}';
  ///
  /// // Import secret key from decoded JSON.
  /// final key = await AesCtrSecretKey.importJsonWebKey(jsonDecode(jwk));
  ///
  /// // Export the key (print it in same format as it was given).
  /// Map<String, dynamic> keyData = await key.exportJsonWebKey();
  /// print(jsonEncode(keyData));
  /// ```
  ///
  /// [1]:https://www.rfc-editor.org//rfc7517
  static Future<AesCtrSecretKey> importJsonWebKey(
      Map<String, dynamic> jwk) async {
    final impl = await webCryptImpl.aesCtrSecretKey.importJsonWebKey(jwk);
    return AesCtrSecretKey._(impl);
  }

  /// Generate random [AesCtrSecretKey].
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
  /// // Generate a new random AES-CTR secret key for AES-256.
  /// final key = await AesCtrSecretKey.generate(256);
  /// ```
  static Future<AesCtrSecretKey> generateKey(int length) async {
    final impl = await webCryptImpl.aesCtrSecretKey.generateKey(length);
    return AesCtrSecretKey._(impl);
  }

  /// Encrypt [data] with this [AesCtrSecretKey] using AES in _Counter mode_,
  /// as specified in [NIST SP800-38A][1].
  ///
  /// {@template AesCtrSecretKey-encrypt:ctr}
  /// The operation requires a 16 bytes _initial counter block_ [counter].
  /// The [length] right most bits of [counter] are incremented for each
  /// encrypted block, the left most 128 - [length] bits are used as a nonce.
  /// The [counter] value must not be reused for subsequent messages, and
  /// the encrypted [data] must not exceed 2 ^ [length] * block-size, as this
  /// would cause counter blocks to be reused.
  /// For detailed discussion of the counter block requirements for
  /// AES-CTR, see [Appendix B of NIST SP800-38A](https://csrc.nist.gov/publications/detail/sp/800-38a/final).
  /// {@endtemplate}
  ///
  /// {@template AesCtrSecretKey-encryptBytes/decryptBytes:example}
  /// **Example**
  /// ```dart
  /// import 'dart:convert' show utf8;
  /// import 'dart:typed_data' show Uint8List;
  /// import 'package:webcrypto/webcrypto.dart';
  ///
  /// // Generate a new random AES-CTR secret key for AES-256.
  /// final k = await AesCtrSecretKey.generate(256);
  ///
  /// // Use a unique counter for each message.
  /// final ctr = Uint8List(16); // always 16 bytes
  /// fillRandomBytes(ctr);
  ///
  /// // Length of the counter, the N'th right most bits of ctr are incremented
  /// // for each block, the left most 128 - N bits are used as static nonce.
  /// // Thus, messages must be less than 2^64 * 16 bytes.
  /// final N = 64;
  ///
  /// // Encrypt a message
  /// final c = await k.encryptBytes(utf8.encode('hello world'), ctr, N);
  ///
  /// // Decrypt message (requires the same counter ctr and length N)
  /// print(utf8.decode(await k.decryptBytes(c, ctr, N))); // hello world
  /// ```
  /// {@endtemplate}
  ///
  /// {@template AesCtrSecretKey-compatibility-notes}
  /// > [!NOTE]
  /// > Firefox does not implement counter rollover for AES-CTR correctly.
  /// Picking a sufficiently large `length` and using a `counter` that isn't
  /// filled with 0xff will likely avoid counter rollovers.
  /// See [bug 1803105](https://bugzilla.mozilla.org/show_bug.cgi?id=1803105) for details.
  /// {@endtemplate}
  ///
  /// [1]: https://csrc.nist.gov/publications/detail/sp/800-38a/final
  // Note. that if counter wraps around, then this is broken on Firefox.
  Future<Uint8List> encryptBytes(
    List<int> data,
    List<int> counter,
    int length,
  ) =>
      _impl.encryptBytes(data, counter, length);

  /// Encrypt [data] with this [AesCtrSecretKey] using AES in _Counter mode_,
  /// as specified in [NIST SP800-38A][1].
  ///
  /// {@macro AesCtrSecretKey-encrypt:ctr}
  ///
  /// {@template AesCtrSecretKey-encryptStream/decryptStream:example}
  /// **Example**
  /// ```dart
  /// import 'dart:io' show File;
  /// import 'dart:convert' show utf8;
  /// import 'dart:typed_data' show Uint8List;
  /// import 'package:async/async.dart' show collectBytes;
  /// import 'package:webcrypto/webcrypto.dart';
  ///
  /// // Generate a new random AES-CTR secret key for AES-256.
  /// final k = await AesCtrSecretKey.generate(256);
  ///
  /// // Use a unique counter for each message.
  /// final ctr = Uint8List(16); // always 16 bytes
  /// fillRandomBytes(ctr);
  ///
  /// // Length of the counter, the N'th right most bits of ctr are incremented
  /// // for each block, the left most 128 - N bits are used as static nonce.
  /// // Thus, messages must be less than 2^64 * 16 bytes.
  /// final N = 64;
  ///
  /// // Encrypt a message from file and write to file
  /// final inputFile = File('message.txt');
  /// final encryptedFile = File('encrypted-message.binary');
  /// final c = await k.encryptStream(
  ///   inputFile.openRead(),
  ///   ctr,
  ///   N,
  /// ).pipe(encryptedFile.openWrite());
  ///
  ///
  /// // Decrypt message (requires the same counter ctr and length N)
  /// final decryptedBytes = await collectBytes(k.decryptStream(
  ///   encryptedFile.openRead(),
  ///   ctr, // same ctr as used for encryption
  ///   N, // same N as used for encryption
  /// ));
  /// // decryptedBytes should be equal to contents of inputFile
  /// assert(utf8.decode(decryptedBytes) == inputFile.readAsStringSync());
  /// ```
  /// {@endtemplate}
  ///
  /// {@macro AesCtrSecretKey-compatibility-notes}
  ///
  /// [1]: https://csrc.nist.gov/publications/detail/sp/800-38a/final
  Stream<Uint8List> encryptStream(
    Stream<List<int>> data,
    List<int> counter,
    int length,
  ) =>
      _impl.encryptStream(data, counter, length);

  /// Decrypt [data] with this [AesCtrSecretKey] using AES in _Counter mode_,
  /// as specified in [NIST SP800-38A][1].
  ///
  /// {@template AesCtrSecretKey-decrypt:ctr}
  /// To decrypt [data] the same _initial counter block_ [counter] and [length]
  /// as was used for encryption must be specified. The [counter] must always
  /// be 16 bytes.
  /// See [encryptBytes] for further discussion of the _initial counter block_
  /// and [length].
  /// {@endtemplate}
  ///
  /// {@macro AesCtrSecretKey-encryptBytes/decryptBytes:example}
  ///
  /// {@macro AesCtrSecretKey-compatibility-notes}
  ///
  /// [1]: https://csrc.nist.gov/publications/detail/sp/800-38a/final
  Future<Uint8List> decryptBytes(
    List<int> data,
    List<int> counter,
    int length,
  ) =>
      _impl.decryptBytes(data, counter, length);

  /// Decrypt [data] with this [AesCtrSecretKey] using AES in _Counter mode_,
  /// as specified in [NIST SP800-38A][1].
  ///
  /// {@macro AesCtrSecretKey-decrypt:ctr}
  ///
  /// {@macro AesCtrSecretKey-encryptStream/decryptStream:example}
  ///
  /// {@macro AesCtrSecretKey-compatibility-notes}
  ///
  /// [1]: https://csrc.nist.gov/publications/detail/sp/800-38a/final
  Stream<Uint8List> decryptStream(
    Stream<List<int>> data,
    List<int> counter,
    int length,
  ) =>
      _impl.decryptStream(data, counter, length);

  /// Export [AesCtrSecretKey] as raw bytes.
  ///
  /// This returns raw bytes making up the secret key.
  ///
  /// **Example**
  /// ```dart
  /// import 'package:webcrypto/webcrypto.dart';
  ///
  /// // Generate a new random AES-256 secret key.
  /// final key = await AesCtrSecretKey.generate(256);
  ///
  /// // Extract the secret key.
  /// final secretBytes = await key.exportRawKey();
  ///
  /// // Print the key as base64
  /// print(base64.encode(secretBytes));
  ///
  /// // If we wanted to we could import the key as follows:
  /// // key = await AesCtrSecretKey.importRawKey(secretBytes);
  /// ```
  Future<Uint8List> exportRawKey() => _impl.exportRawKey();

  /// Export [AesCtrSecretKey] as [JSON Web Key][1].
  ///
  /// {@macro exportJsonWebKey:returns}
  ///
  /// **Example**
  /// ```dart
  /// import 'package:webcrypto/webcrypto.dart';
  /// import 'dart:convert' show jsonEncode;
  ///
  /// // Generate a new random AES-256 secret key.
  /// final key = await AesCtrSecretKey.generate(256);
  ///
  /// // Export the secret key.
  /// final jwk = await key.exportJsonWebKey();
  ///
  /// // The Map returned by `exportJsonWebKey()` can be converted to JSON with
  /// // `jsonEncode` from `dart:convert`, this will print something like:
  /// // {"kty": "oct", "alg": "A256CTR", "k": ...}
  /// print(jsonEncode(jwk));
  /// ```
  ///
  /// [1]:https://www.rfc-editor.org//rfc7517
  Future<Map<String, dynamic>> exportJsonWebKey() => _impl.exportJsonWebKey();
}
