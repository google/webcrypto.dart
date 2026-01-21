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

/// AES secret for symmetric encryption and decryption using AES in
/// _Galois/Counter Mode_ (GCM-mode), as described in [NIST SP 800-38D][1].
///
/// An [AesGcmSecretKey] can be imported from:
///  * Raw bytes using [AesGcmSecretKey.importRawKey], and,
///  * [JWK][2] format using [AesGcmSecretKey.importJsonWebKey].
///
/// A random [AesGcmSecretKey] can be generated using
/// [AesGcmSecretKey.generateKey].
///
/// AES in GCM-mode is an [authenticated encryption][3] cipher, this means that
/// that it includes checks that the ciphertext has not been modified.
///
/// {@macro AesGcmSecretKey-encryptBytes/decryptBytes:example}
///
/// [1]: https://csrc.nist.gov/pubs/sp/800/38/d/final
/// [2]: https://datatracker.ietf.org/doc/html/rfc7517
/// [3]: https://en.wikipedia.org/wiki/Authenticated_encryption
final class AesGcmSecretKey {
  final AesGcmSecretKeyImpl _impl;

  AesGcmSecretKey._(this._impl); // keep the constructor private.

  /// Import an [AesGcmSecretKey] from raw [keyData].
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
  /// final k = await AesGcmSecretKey.importRawKey(rawKey);
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
  static Future<AesGcmSecretKey> importRawKey(List<int> keyData) async {
    final impl = await webCryptImpl.aesGcmSecretKey.importRawKey(keyData);
    return AesGcmSecretKey._(impl);
  }

  /// Import an [AesGcmSecretKey] from [JSON Web Key][1].
  ///
  /// JSON Web Keys imported using [AesGcmSecretKey.importJsonWebKey]
  /// must have `"kty": "oct"`, and the `"alg"` property of the imported [jwk]
  /// must be either:
  ///  * `"alg": "A128GCM"` for AES-128, or
  ///  * `"alg": "A256GCM"` for AES-256.
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
  /// final jwk = '{"kty": "oct", "alg": "A256GCM", "k": ...}';
  ///
  /// // Import secret key from decoded JSON.
  /// final key = await AesGcmSecretKey.importJsonWebKey(jsonDecode(jwk));
  ///
  /// // Export the key (print it in same format as it was given).
  /// Map<String, dynamic> keyData = await key.exportJsonWebKey();
  /// print(jsonEncode(keyData));
  /// ```
  ///
  /// [1]: https://datatracker.ietf.org/doc/html/rfc7517
  static Future<AesGcmSecretKey> importJsonWebKey(
    Map<String, dynamic> jwk,
  ) async {
    final impl = await webCryptImpl.aesGcmSecretKey.importJsonWebKey(jwk);
    return AesGcmSecretKey._(impl);
  }

  /// Generate a random [AesGcmSecretKey].
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
  /// // Generate a new random AES-GCM secret key for AES-256.
  /// final key = await AesGcmSecretKey.generate(256);
  /// ```
  static Future<AesGcmSecretKey> generateKey(int length) async {
    final impl = await webCryptImpl.aesGcmSecretKey.generateKey(length);
    return AesGcmSecretKey._(impl);
  }

  /// Encrypt [data] with this [AesCbcSecretKey] using AES in
  /// _Galois/Counter Mode_ (GCM-mode), as specified in [NIST SP 800-38D][1].
  ///
  /// This operation requires an _initalization vector_ [iv]. The [iv]
  /// needs not be secret, but it must unique for each invocation.
  /// In particular the same (key, [iv]) pair must **not** be used more than once.
  /// For detailed discussion of the initialization vector requirements for
  /// AES-GCM, see [Appendix A of NIST SP 800-38D][1].
  ///
  /// The [additionalData] parameter is optional, and is used to provide
  /// _additional authenticated data_ (also called _associated data_) for
  /// the encryption operation. Unlike the plaintext [data], the
  /// [additionalData] is not encrypted. But integrity of the [additionalData]
  /// is protected. Meaning that decryption will not succeed if [additionalData]
  /// has be modified.
  /// In an [authenticated encryption][2] scheme [additionalData] is typically
  /// used to encode a IP, port, headers, date-time, a sequence number or
  /// similar data that indicates how the ciphertext should be used.
  /// As such [additionalData] aims to stop the ciphertext from being used
  /// out of context.
  ///
  /// This operation requires a [tagLength], which specifies the bit-length
  /// of the resulting authentication tag.
  /// The permitted values for [tagLength] are:
  ///  * `32` bits,
  ///  * `64` bits,
  ///  * `96` bits,
  ///  * `104` bits,
  ///  * `112` bits,
  ///  * `120` bits, or,
  ///  * `128` bits (default).
  ///
  /// This tag ensures the authenticity of the plaintext and the
  /// [additionalData]. A short tag, may decrease these assurances.
  /// For a discussion of [tagLength] and security assurances,
  /// see [Appendix B of NIST SP 800-38D][1].
  ///
  /// This methods returns a [Uint8List] that is the concatenation of the
  /// _ciphertext_ and the _authentication tag_.
  /// That is, if you use a default [tagLength] of `128`, then the last 16 bytes
  /// of the return value makes up the _authentication tag_.
  ///
  /// {@template AesGcmSecretKey-encryptBytes/decryptBytes:example}
  /// **Example**
  /// ```dart
  /// import 'dart:convert' show utf8;
  /// import 'dart:typed_data' show Uint8List;
  /// import 'package:webcrypto/webcrypto.dart';
  ///
  /// // Generate a new random AES-GCM secret key for AES-256.
  /// final k = await AesGcmSecretKey.generate(256);
  ///
  /// // Use a unique IV for each message.
  /// final iv = Uint8List(16);
  /// fillRandomBytes(iv);
  ///
  /// // Specify optional additionalData
  /// final ad = utf8.encode('my-test-message');
  ///
  /// // Encrypt a message
  /// final c = await k.encryptBytes(
  ///   utf8.encode('hello world'),
  ///   iv,
  ///   additionalData: ad,
  /// );
  ///
  /// // Decrypt message (requires the same iv)
  /// print(utf8.decode(await k.decryptBytes(
  ///   c,
  ///   iv,
  ///   additionalData: ad,
  /// ))); // hello world
  /// ```
  /// {@endtemplate}
  ///
  /// {@template AesGcmSecretKey-remark:no-stream-api}
  /// > [!NOTE]
  /// > This package does not offer a streaming API for
  /// encryption / decryption using AES-GCM, because reading deciphered
  /// plaintext prior to complete verification of the tag breaks the
  /// authenticity assurances. Specifically, until the entire message is
  /// decrypted it is not possible to know if it is authentic, which would
  /// defeat the purpose of _authenticated encryption_.
  /// {@endtemplate}
  ///
  /// [1]: https://csrc.nist.gov/pubs/sp/800/38/d/final
  /// [2]: https://en.wikipedia.org/wiki/Authenticated_encryption
  Future<Uint8List> encryptBytes(
    List<int> data,
    List<int> iv, {
    List<int>? additionalData,
    int? tagLength = 128,
  }) => _impl.encryptBytes(
    data,
    iv,
    additionalData: additionalData,
    tagLength: tagLength,
  );

  // TODO: Document this method, notice that [data] must be concatenation of
  //       ciphertext and authentication tag.
  // TODO: Document what happens if the authenticity validation fails? Some Exception?
  Future<Uint8List> decryptBytes(
    List<int> data,
    List<int> iv, {
    List<int>? additionalData,
    int? tagLength = 128,
  }) => _impl.decryptBytes(
    data,
    iv,
    additionalData: additionalData,
    tagLength: tagLength,
  );

  /// Export [AesGcmSecretKey] as raw bytes.
  ///
  /// This returns raw bytes making up the secret key.
  ///
  /// **Example**
  /// ```dart
  /// import 'package:webcrypto/webcrypto.dart';
  ///
  /// // Generate a new random AES-256 secret key.
  /// final key = await AesGcmSecretKey.generate(256);
  ///
  /// // Extract the secret key.
  /// final secretBytes = await key.exportRawKey();
  ///
  /// // Print the key as base64
  /// print(base64.encode(secretBytes));
  ///
  /// // If we wanted to we could import the key as follows:
  /// // key = await AesGcmSecretKey.importRawKey(secretBytes);
  /// ```
  Future<Uint8List> exportRawKey() => _impl.exportRawKey();

  /// Export [AesGcmSecretKey] as [JSON Web Key][1].
  ///
  /// {@macro exportJsonWebKey:returns}
  ///
  /// **Example**
  /// ```dart
  /// import 'package:webcrypto/webcrypto.dart';
  /// import 'dart:convert' show jsonEncode;
  ///
  /// // Generate a new random AES-256 secret key.
  /// final key = await AesGcmSecretKey.generate(256);
  ///
  /// // Export the secret key.
  /// final jwk = await key.exportJsonWebKey();
  ///
  /// // The Map returned by `exportJsonWebKey()` can be converted to JSON with
  /// // `jsonEncode` from `dart:convert`, this will print something like:
  /// // {"kty": "oct", "alg": "A256GCM", "k": ...}
  /// print(jsonEncode(jwk));
  /// ```
  ///
  /// [1]: https://datatracker.ietf.org/doc/html/rfc7517
  Future<Map<String, dynamic>> exportJsonWebKey() => _impl.exportJsonWebKey();
}
