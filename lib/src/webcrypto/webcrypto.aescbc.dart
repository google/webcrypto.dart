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
/// _Cipher Block Chaining mode_ (CBC-mode), as described in [NIST SP800-38A].
///
/// Encrypted messages are always padded in PKCS#7 mode, as described in
/// [RFC 2315 Section 10.3 step 2][rfc-2315-10.3]. This padding is stripped when
/// the message is decrypted.
///
/// Instances of [AesCbcSecretKey] can be imported using
/// [AesCbcSecretKey.importRawKey] and [AesCbcSecretKey.importJsonWebKey], or
/// generated using [AesCbcSecretKey.generateKey].
///
/// [NIST SP800-38A]: https://csrc.nist.gov/publications/detail/sp/800-38a/final
/// [rfc-2315-10.3]: https://tools.ietf.org/html/rfc2315#section-10.3
@sealed
abstract class AesCbcSecretKey {
  AesCbcSecretKey._(); // keep the constructor private.

  /// Import an [AesCbcSecretKey] from raw [keyData].
  ///
  /// [KeyData] must be either:
  ///  * 16 bytes (128 bit) for AES-128, or,
  ///  * 32 bytes (256 bit) for AES-256.
  ///
  /// Support for AES-192 (24 byte keys) is [intentionally omitted by Chrome][1],
  /// and will therefore not be supported by `package:webcrypto`.
  ///
  /// **Example**
  /// ```dart
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
  ///
  /// [1]: https://crbug.com/533699
  static Future<AesCbcSecretKey> importRawKey(List<int> keyData) {
    ArgumentError.checkNotNull(keyData, 'keyData');

    return impl.aesCbc_importRawKey(keyData);
  }

  static Future<AesCbcSecretKey> importJsonWebKey(Map<String, dynamic> jwk) {
    ArgumentError.checkNotNull(jwk, 'jwk');

    return impl.aesCbc_importJsonWebKey(jwk);
  }

  static Future<AesCbcSecretKey> generateKey(int length) {
    ArgumentError.checkNotNull(length, 'length');

    return impl.aesCbc_generateKey(length);
  }

  Future<Uint8List> encryptBytes(List<int> data, List<int> iv);

  Stream<Uint8List> encryptStream(Stream<List<int>> data, List<int> iv);

  Future<Uint8List> decryptBytes(List<int> data, List<int> iv);

  Stream<Uint8List> decryptStream(Stream<List<int>> data, List<int> iv);

  Future<Uint8List> exportRawKey();

  Future<Map<String, dynamic>> exportJsonWebKey();
}
