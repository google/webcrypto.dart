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

/// PBKDF2 secret key (or password) for key derivation.
///
/// An [Pbkdf2SecretKey] instance holds a secret key for key derivation using
/// _PKCS#5 password-based key derivation function version 2_ as specified in
/// [RFC 8018][1] using HMAC as pseudo-random function. The HMAC will used the
/// [Hash] algorithm given in [deriveBits].
///
/// A [Pbkdf2SecretKey] can be imported using [importRawKey].
///
/// {@template Pbkdf2SecretKey:example}
/// **Example**
/// ```
/// import 'dart:convert' show utf8, base64;
/// import 'package:webcrypto/webcrypto.dart';
///
/// // Provide a password to be used for key derivation
/// final key = await Pbkdf2SecretKey.importRawKey(utf8.decode(
///   'my-password-in-plain-text',
/// ));
///
/// // Derive a key from password
/// final derivedKey = await Pbkdf2SecretKey.deriveBits(
///   256, // number of bits to derive.
///   Hash.sha256,
///   utf8.decode('unique salt'),
///   100000,
/// );
///
/// // Print the derived key, this could also be used as basis for other new
/// // symmetric cryptographic keys.
/// print(base64.encode(derivedKey));
/// ```
/// {@endtemplate}
///
/// [1]: https://tools.ietf.org/html/rfc8018
// TODO: Rewrite all RFC links to use https://www.rfc-editor.org/rfc/rfcXXXX
@sealed
abstract class Pbkdf2SecretKey {
  Pbkdf2SecretKey._(); // keep the constructor private.

  /// Import [Pbkdf2SecretKey] from raw [keyData].
  ///
  /// Creates a [Pbkdf2SecretKey] for key derivation using [keyData].
  ///
  /// {@macro Pbkdf2SecretKey:example}
  static Future<Pbkdf2SecretKey> importRawKey(List<int> keyData) {
    return impl.pbkdf2SecretKey_importRawKey(keyData);
  }

  /// Derive key from [salt] and password specified as `keyData` in
  /// [importRawKey].
  ///
  /// The [length] of the key to be derived must be specified in bits as a
  /// multiple of 8.
  ///
  /// The key derivation will used HMAC with given [hash] as the
  /// _pseudo-random function_.
  ///
  /// Using sufficiently large random [salt] makes hard for an adversary to
  /// precompute the most likely keys using a dictionary of common passwords.
  /// The [salt] also serves make the same password have yield different keys.
  /// For details on [salt] see [RFC 8018 section 4.1][1].
  ///
  /// A higher [iterations] count will increase the cost to an adversary doing
  /// an exhaustive search for the derived key, but it will also make the
  /// key derivation operation slower. For details on [iterations] see
  /// [RFC 8018 section 4.2][1].
  ///
  /// {@macro Pbkdf2SecretKey:example}
  ///
  /// [1]: https://tools.ietf.org/html/rfc8018
  Future<Uint8List> deriveBits(
    int length,
    Hash hash,
    List<int> salt,
    int iterations,
  );
}
