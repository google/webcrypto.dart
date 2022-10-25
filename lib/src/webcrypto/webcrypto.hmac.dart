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

/// Key for signing/verifying with HMAC.
///
/// An [HmacSecretKey] instance holds a symmetric secret key and a
/// [Hash], which can be used to create and verify HMAC signatures as
/// specified in [FIPS PUB 180-4][1].
///
/// Instances of [HmacSecretKey] can be imported from:
///  * Raw bytes using [HmacSecretKey.importRawKey], and,
///  * [JWK] format using [HmacSecretKey.importJsonWebKey].
///
/// A random key can also be generated using [HmacSecretKey.generateKey].
///
/// [1]: https://doi.org/10.6028/NIST.FIPS.180-4
@sealed
abstract class HmacSecretKey {
  HmacSecretKey._(); // keep the constructor private.

  /// Import [HmacSecretKey] from raw [keyData].
  ///
  /// Creates an [HmacSecretKey] using [keyData] as secret key, and running
  /// HMAC with given [hash] algorithm.
  ///
  /// If given, [length] specifies the length of the key, this must be not be
  /// less than number of bits in [keyData] - 7. The [length] only allows
  /// cutting bits of the last byte in [keyData]. In practice this is the same
  /// as zero'ing the last bits in [keyData].
  ///
  /// **Example**
  /// ```dart
  /// import 'dart:convert' show utf8;
  /// import 'package:webcrypto/webcrypto.dart';
  ///
  /// final key = await HmacSecretKey.importRawKey(
  ///   base64.decode('WzIxLDg0LDEwMCw5OSwxMCwxMDUsMjIsODAsMTkwLDExNiwyMDMsMjQ5XQ=='),
  ///   Hash.sha256,
  /// );
  /// ```
  static Future<HmacSecretKey> importRawKey(
    List<int> keyData,
    Hash hash, {
    int? length,
  }) {
    // These limitations are given in Web Cryptography Spec:
    // https://www.w3.org/TR/WebCryptoAPI/#hmac-operations
    if (length != null && length > keyData.length * 8) {
      throw ArgumentError.value(
          length, 'length', 'must be less than number of bits in keyData');
    }
    if (length != null && length <= (keyData.length - 1) * 8) {
      throw ArgumentError.value(
        length,
        'length',
        'must be greater than number of bits in keyData - 8, you can attain '
            'the same effect by removing bytes from keyData',
      );
    }

    return impl.hmacSecretKey_importRawKey(keyData, hash, length: length);
  }

  /// Import [HmacSecretKey] from [JSON Web Key][1].
  ///
  /// {@macro importJsonWebKey:jwk}
  ///
  /// JSON Web Keys imported using [HmacSecretKey.importJsonWebKey] must
  /// have `"kty": "oct"`, and the [hash] given must match the hash algorithm
  /// implied by the `"alg"` property of the imported [jwk].
  ///
  /// For importing a JWK with:
  ///  * `"alg": "HS1"` use [Hash.sha1] (**SHA-1 is weak**),
  ///  * `"alg": "HS256"` use [Hash.sha256],
  ///  * `"alg": "HS384"` use [Hash.sha384], and,
  ///  * `"alg": "HS512"` use [Hash.sha512].
  ///
  /// If specified the `"use"` property of the imported [jwk] must be
  /// `"use": "sig"`.
  ///
  /// {@macro importJsonWebKey:throws-FormatException-if-jwk}
  ///
  /// **Example**
  /// ```dart
  /// import 'package:webcrypto/webcrypto.dart';
  /// import 'dart:convert' show jsonEncode, jsonDecode;
  ///
  /// // JSON Web Key as a string containing JSON.
  /// final jwk = '{"kty": "oct", "alg": "HS256", "k": ...}';
  ///
  /// // Import secret key from decoded JSON.
  /// final key = await HmacSecretKey.importJsonWebKey(
  ///   jsonDecode(jwk),
  ///   Hash.sha256, // Must match the hash used the JWK key "alg"
  /// );
  ///
  /// // Export the key (print it in same format as it was given).
  /// Map<String, dynamic> keyData = await key.exportJsonWebKey();
  /// print(jsonEncode(keyData));
  /// ```
  ///
  /// [1]: https://tools.ietf.org/html/rfc7517
  static Future<HmacSecretKey> importJsonWebKey(
    // TODO: Determine if the "alg" property can be omitted, and update documentation accordingly
    //       also make tests covering cases where "alg" is omitted.
    // TODO: Determine if there is any restrictions on "use" and "key_ops".
    Map<String, dynamic> jwk,
    // TODO: Discuss if hash parameter is really necessary, it's in the JWK.
    //       Presumably webcrypto requires as a sanity check. Notice, that this
    //       should be consistent with other JWK imports, where we specify curve
    //       or other parameters. Either we read from JWK, or we verify that
    //       what is in the JWK matches what is also given.
    //       Note. it's not yet clear if JWK always contains key parameters.
    Hash hash, {
    int? length,
  }) {
    /*
    TODO: Validate these in the native implememtation
    // These limitations are given in Web Cryptography Spec:
    // https://www.w3.org/TR/WebCryptoAPI/#hmac-operations
    if (length != null && length > keyData.length * 8) {
      throw ArgumentError.value(
          length, 'length', 'must be less than number of bits in keyData');
    }
    if (length != null && length <= (keyData.length - 1) * 8) {
      throw ArgumentError.value(
        length,
        'length',
        'must be greater than number of bits in keyData - 8, you can attain '
            'the same effect by removing bytes from keyData',
      );
    }*/

    return impl.hmacSecretKey_importJsonWebKey(jwk, hash, length: length);
  }

  /// Generate random [HmacSecretKey].
  ///
  /// The [length] specifies the length of the secret key in bits. If omitted
  /// the random key will use the same number of bits as the underlying hash
  /// algorithm given in [hash].
  ///
  /// **Example**
  /// ```dart
  /// import 'package:webcrypto/webcrypto.dart';
  ///
  /// // Generate a new random HMAC secret key.
  /// final key = await HmacSecretKey.generate(Hash.sha256);
  /// ```
  static Future<HmacSecretKey> generateKey(Hash hash, {int? length}) {
    if (length != null && length <= 0) {
      throw ArgumentError.value(length, 'length', 'must be positive');
    }

    return impl.hmacSecretKey_generateKey(hash, length: length);
  }

  /// Compute an HMAC signature of given [data].
  ///
  /// This computes an HMAC signature of the [data] using hash algorithm
  /// and secret key material held by this [HmacSecretKey].
  ///
  /// **Example**
  /// ```dart
  /// import 'dart:convert' show base64, utf8;
  /// import 'package:webcrypto/webcrypto.dart';
  ///
  /// // Generate an HmacSecretKey.
  /// final key = await HmacSecretKey.generateKey(Hash.sha256);
  ///
  /// String stringToSign = 'example-string-to-signed';
  ///
  /// // Compute signature.
  /// final signature = await key.signBytes(utf8.encode(stringToSign));
  ///
  /// // Print as base64
  /// print(base64.encode(signature));
  /// ```
  ///
  /// {@template HMAC-sign:do-not-validate-using-sign}
  /// This method should not be used for **validating** other signatures by
  /// generating a new signature and then comparing the two signatures.
  /// While this technically works, your application might be vulnerable to
  /// timing attacks. To validate signatures use [verifyBytes] or [verifyStream]
  /// instead, these methods computes a signature and does a
  /// fixed-time comparison.
  /// {@template}
  Future<Uint8List> signBytes(List<int> data);

  /// Compute an HMAC signature of given [data] stream.
  ///
  /// This computes an HMAC signature of the [data] stream using hash algorithm
  /// and secret key material held by this [HmacSecretKey].
  ///
  /// **Example**
  /// ```dart
  /// import 'dart:convert' show base64, utf8;
  /// import 'package:webcrypto/webcrypto.dart';
  ///
  /// // Generate an HmacSecretKey.
  /// final key = await HmacSecretKey.generateKey(Hash.sha256);
  ///
  /// String stringToSign = 'example-string-to-signed';
  ///
  /// // Compute signature.
  /// final signature = await key.signStream(Stream.fromIterable([
  ///   utf8.encode(stringToSign),
  /// ]));
  ///
  /// // Print as base64
  /// print(base64.encode(signature));
  /// ```
  ///
  /// {@macro HMAC-sign:do-not-validate-using-sign}
  Future<Uint8List> signStream(Stream<List<int>> data);

  /// Verify the HMAC [signature] of given [data].
  ///
  /// This computes an HMAC signature of the [data] in the same manner
  /// as [signBytes] and conducts a fixed-time comparison against [signature],
  /// returning `true` if the two signatures are equal.
  ///
  /// {@template HMAC-verify:do-not-validate-using-sign}
  /// It is possible to compute a signature for [data] using
  /// [signBytes] or [signStream] and then simply compare the two signatures.
  /// This is strongly discouraged as it is easy to introduce side-channels
  /// opening your application to timing attacks.
  /// Use [verifyBytes] or [verifyStream] to verify signatures.
  /// {@endtemplate}
  ///
  /// **Example**
  /// ```dart
  /// import 'dart:convert' show base64, utf8;
  /// import 'package:webcrypto/webcrypto.dart';
  ///
  /// // Generate an HmacSecretKey.
  /// final key = await HmacSecretKey.generateKey(Hash.sha256);
  ///
  /// String stringToSign = 'example-string-to-signed';
  ///
  /// // Compute signature.
  /// final signature = await key.signBytes(utf8.encode(stringToSign));
  ///
  /// // Verify signature.
  /// final result = await key.verifyBytes(
  ///   signature,
  ///   utf8.encode(stringToSign),
  /// );
  /// assert(result == true, 'this signature should be valid');
  /// ```
  Future<bool> verifyBytes(List<int> signature, List<int> data);

  /// Verify the HMAC [signature] of given [data] stream.
  ///
  /// This computes an HMAC signature of the [data] stream in the same manner
  /// as [signStream] and conducts a fixed-time comparison against [signature],
  /// returning `true` if the two signatures are equal.
  ///
  /// {@macro HMAC-verify:do-not-validate-using-sign}
  ///
  /// **Example**
  /// ```dart
  /// import 'dart:convert' show base64, utf8;
  /// import 'package:webcrypto/webcrypto.dart';
  ///
  /// // Generate an HmacSecretKey.
  /// final key = await HmacSecretKey.generateKey(Hash.sha256);
  ///
  /// String stringToSign = 'example-string-to-signed';
  ///
  /// // Compute signature.
  /// final signature = await key.signBytes(Stream.fromIterable([
  ///   utf8.encode(stringToSign),
  /// ]));
  ///
  /// // Verify signature.
  /// final result = await key.verifyStream(signature, Stream.fromIterable([
  ///   utf8.encode(stringToSign),
  /// ]));
  /// assert(result == true, 'this signature should be valid');
  /// ```
  Future<bool> verifyStream(List<int> signature, Stream<List<int>> data);

  /// Export [HmacSecretKey] as raw bytes.
  ///
  /// This returns raw bytes making up the secret key. This does not encode the
  /// [Hash] hash algorithm used.
  ///
  /// **Example**
  /// ```dart
  /// import 'package:webcrypto/webcrypto.dart';
  ///
  /// // Generate a new random HMAC secret key.
  /// final key = await HmacSecretKey.generate(Hash.sha256);
  ///
  /// // Extract the secret key.
  /// final secretBytes = await key.exportRawKey();
  ///
  /// // Print the key as base64
  /// print(base64.encode(secretBytes));
  ///
  /// // If we wanted to we could import the key as follows:
  /// // key = await HmacSecretKey.importRawKey(secretBytes, Hash.sha256);
  /// ```
  Future<Uint8List> exportRawKey();

  /// Export [HmacSecretKey] as [JSON Web Key][1].
  ///
  /// {@macro exportJsonWebKey:returns}
  ///
  /// **Example**
  /// ```dart
  /// import 'package:webcrypto/webcrypto.dart';
  /// import 'dart:convert' show jsonEncode;
  ///
  /// // Generate a new random HMAC secret key.
  /// final key = await HmacSecretKey.generate(Hash.sha256);
  ///
  /// // Export the secret key.
  /// final jwk = await key.exportJsonWebKey();
  ///
  /// // The Map returned by `exportJsonWebKey()` can be converted to JSON with
  /// // `jsonEncode` from `dart:convert`, this will print something like:
  /// // {"kty": "oct", "alg": "HS256", "k": ...}
  /// print(jsonEncode(jwk));
  /// ```
  ///
  /// [1]: https://tools.ietf.org/html/rfc7517
  Future<Map<String, dynamic>> exportJsonWebKey();
}
