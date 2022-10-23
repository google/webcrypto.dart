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

/// HKDF secret key (or password) for key derivation.
///
/// An [HkdfSecretKey] instance holds a secret key for key derivation using
/// the _HMAC-based Key Derivation Function_ specified in [RFC 5869][1] using
/// a [Hash] function specified in the [deriveBits] method.
///
/// A [HkdfSecretKey] can be imported using [importRawKey].
///
/// {@template HkdfSecretKey:example}
/// **Example**
/// ```
/// import 'dart:convert' show utf8, base64;
/// import 'package:webcrypto/webcrypto.dart';
///
/// // Provide a password to be used for key derivation
/// final key = await HkdfSecretKey.importRawKey(utf8.decode(
///   'my-password-in-plain-text',
/// ));
///
/// // Derive a key from password
/// final derivedKey = await HkdfSecretKey.deriveBits(
///   256, // number of bits to derive.
///   Hash.sha256,
///   utf8.decode('unique salt'),
///   utf8.decode('creating derivedKey in example'),
/// );
///
/// // Print the derived key, this could also be used as basis for other new
/// // symmetric cryptographic keys.
/// print(base64.encode(derivedKey));
/// ```
/// {@endtemplate}
///
/// [1]: https://tools.ietf.org/html/rfc5869
// TODO: It might be wise to use a random salt, then suggest that the non-secret
//       salt is stored or exchanged...
@sealed
abstract class HkdfSecretKey {
  HkdfSecretKey._(); // keep the constructor private.

  /// Import [HkdfSecretKey] from raw [keyData].
  ///
  /// Creates a [HkdfSecretKey] for key derivation using [keyData].
  ///
  /// {@macro HkdfSecretKey:example}
  static Future<HkdfSecretKey> importRawKey(List<int> keyData) {
    return impl.hkdfSecretKey_importRawKey(keyData);
  }

  /// Derive key from [salt], [info] and password specified as `keyData` in
  /// [importRawKey].
  ///
  /// The [length] of the key to be derived must be specified in bits as a
  /// multiple of 8.
  ///
  /// Using sufficiently large random [salt] makes hard for an adversary to
  /// precompute the most likely keys using a dictionary of common passwords.
  /// The [salt] also serves make the same password have yield different keys.
  /// For details on [salt] see [RFC 5869 section 3.1][1].
  ///
  /// The [info] serves to bind the derived key to an application specific
  /// context. For example, if the same `keyData` is used to derive keys for
  /// different use cases, then using a different [info] for each purpose
  /// ensures that the derived keys are different.
  /// For details on [info] see [RFC 5869 section 3.2][2].
  ///
  /// {@macro HkdfSecretKey:example}
  ///
  /// [1]: https://www.rfc-editor.org/rfc/rfc5869#section-3.1
  /// [2]: https://www.rfc-editor.org/rfc/rfc5869#section-3.2
  Future<Uint8List> deriveBits(
    int length,
    Hash hash,
    List<int> salt,
    List<int> info,
  );
}
