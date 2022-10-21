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

/// RSASSA-PKCS1-v1_5 private key for signing messages.
///
/// An [RsassaPkcs1V15PrivateKey] instance hold a private RSA key for computing
/// signatures using the RSASSA-PKCS1-v1_5 scheme as specified in [RFC 3447][1].
///
/// An [RsassaPkcs1V15PrivateKey] can be imported from:
///  * [PKCS #8][2] format using [RsassaPkcs1V15PrivateKey.importPkcs8Key], and,
///  * [JWK][3] format using [RsassaPkcs1V15PrivateKey.importJsonWebKey].
///
/// A public-private [KeyPair] consisting of a [RsassaPkcs1V15PublicKey] and a
/// [RsassaPkcs1V15PrivateKey] can be generated using
/// [RsassaPkcs1V15PrivateKey.generateKey].
///
/// {@template RSASSA-PKCS1-v1_5-Example:generate-sign-verify}
/// **Example**
/// ```dart
/// import 'dart:convert' show utf8;
/// import 'package:webcrypto/webcrypto.dart';
///
/// // Generate a key-pair.
/// final keyPair = await RsassaPkcs1V15PrivateKey.generateKey(
///   4096,
///   BigInt.from(65537),
///   Hash.sha256,
/// );
///
/// // Using privateKey Bob can sign a message for Alice.
/// final message = 'Hi Alice';
/// final signature = await keyPair.privateKey.signBytes(utf8.encode(message));
///
/// // Given publicKey and signature Alice can verify the message from Bob.
/// final isValid = await keypair.publicKey.verifyBytes(
///   signature,
///   utf8.encode(message),
/// );
/// if (isValid) {
///   print('Authentic message from Bob: $message');
/// }
/// ```
/// {@endtemplate}
///
/// [1]: https://tools.ietf.org/html/rfc3447
/// [2]: https://tools.ietf.org/html/rfc5208
/// [3]: https://tools.ietf.org/html/rfc7517
@sealed
abstract class RsassaPkcs1V15PrivateKey {
  RsassaPkcs1V15PrivateKey._(); // keep the constructor private.

  /// Import RSASSA-PKCS1-v1_5 private key in PKCS #8 format.
  ///
  /// Creates an [RsassaPkcs1V15PrivateKey] from [keyData] given as the DER
  /// encoding of the _PrivateKeyInfo structure_ specified in [RFC 5208][1].
  /// The hash algorithm to be used is specified by [hash].
  ///
  /// {@template RSA-importKey:throws-FormatException-if-KeyData}
  /// Throws [FormatException] if [keyData] is invalid.
  /// {@endtemplate}
  ///
  /// **Example**
  /// ```dart
  /// import 'package:webcrypto/webcrypto.dart';
  /// import 'package:pem/pem.dart';
  ///
  /// // Read key data from PEM encoded block. This will remove the
  /// // '----BEGIN...' padding, decode base64 and return encoded bytes.
  /// List<int> keyData = PemCodec(PemLabel.privateKey).decode("""
  ///   -----BEGIN PRIVATE KEY-----
  ///   MIGEAgEAMBAGByqG...
  ///   -----END PRIVATE KEY-----
  /// """);
  ///
  /// // Import private key from binary PEM decoded data.
  /// final privateKey = await RsassaPkcs1V15PrivateKey.importPkcs8Key(
  ///   keyData,
  ///   Hash.sha256,
  /// );
  ///
  /// // Export the key again (print it in same format as it was given).
  /// List<int> rawKeyData = await privateKey.exportPkcs8Key();
  /// print(PemCodec(PemLabel.privateKey).encode(rawKeyData));
  /// ```
  ///
  /// [1]: https://tools.ietf.org/html/rfc5208
  static Future<RsassaPkcs1V15PrivateKey> importPkcs8Key(
    List<int> keyData,
    Hash hash,
  ) {
    return impl.rsassaPkcs1V15PrivateKey_importPkcs8Key(keyData, hash);
  }

  /// Import RSASSA-PKCS1-v1_5 private key in [JSON Web Key][1] format.
  ///
  /// {@template importJsonWebKey:jwk}
  /// The [jwk] should be given as [Map], [String], [List] the same way
  /// [jsonDecode] from `dart:convert` represents decoded JSON values.
  /// The hash algorithm to be used is specified by [hash].
  /// {@endtemplate}
  ///
  /// JSON Web Keys imported using [RsassaPkcs1V15PrivateKey.importJsonWebKey]
  /// must have `"kty": "RSA"`, and the [hash] given must match the hash
  /// algorithm implied by the `"alg"` property of the imported [jwk].
  ///
  /// {@template RSASSA-PKCS1-v1_5-importJsonWebKey:jwk-alg-list}
  /// For importing a JWK with:
  ///  * `"alg": "RS1"` use [Hash.sha1] (**SHA-1 is weak**),
  ///  * `"alg": "RS256"` use [Hash.sha256],
  ///  * `"alg": "RS384"` use [Hash.sha384], and,
  ///  * `"alg": "RS512"` use [Hash.sha512].
  /// {@endtemplate}
  ///
  /// {@template importJsonWebKey:throws-FormatException-if-jwk}
  /// Throws [FormatException] if [jwk] is invalid.
  /// {@endtemplate}
  ///
  /// **Example**
  /// ```dart
  /// import 'package:webcrypto/webcrypto.dart';
  /// import 'dart:convert' show jsonEncode, jsonDecode;
  ///
  /// // JSON Web Key as a string containing JSON.
  /// final jwk = '{"kty": "RSA", "alg": "RS256", ...}';
  ///
  /// // Import private key from decoded JSON.
  /// final privateKey = await RsassaPkcs1V15PrivateKey.importJsonWebKey(
  ///   jsonDecode(jwk),
  ///   Hash.sha256, // Must match the hash used the JWK key "alg"
  /// );
  ///
  /// // Export the key (print it in same format as it was given).
  /// Map<String, dynamic> keyData = await privateKey.exportJsonWebKey();
  /// print(jsonEncode(keyData));
  /// ```
  ///
  /// {@template RSA-importJsonWebKey:use-key_ops}
  /// **Warning**, the `"use"` and `"key_ops"` properties from the [jwk],
  /// specifying intended usage for public keys and allowed key operations,
  /// are ignored. If these properties are present they will have no effect.
  /// This is also the case when running on the web, as they will be stripped
  /// before the JWK is passed to the browser.
  /// {@endtemplate}
  ///
  /// [1]: https://tools.ietf.org/html/rfc7517
  static Future<RsassaPkcs1V15PrivateKey> importJsonWebKey(
    Map<String, dynamic> jwk,
    Hash hash,
  ) {
    return impl.rsassaPkcs1V15PrivateKey_importJsonWebKey(jwk, hash);
  }

  /// Generate an RSASSA-PKCS1-v1_5 public/private key-pair.
  ///
  /// {@template RSA-generateKey:modulusLength-publicExponent-hash}
  /// The [modulusLength], given in bits, determines the size of the RSA key.
  /// A larger key size (higher [modulusLength]) is often consider more secure,
  /// but generally associated with decreased performance. This can be
  /// particularly noticible during key-generation on limited devices CPUs.
  ///
  /// Using a [modulusLength] less than `2048` is often discouraged
  /// (see [NIST SP 800-57 Part 1 Rev 5, section 5.6][nist-sp]). Common key size
  /// include `2048`, `3072` and `4096` for guidance on key-size see
  /// [NIST SP 800-57 Part 1 Rev 5][nist-sp] or [keylength.com][keylength]
  /// for a comparison of various recommendations.
  ///
  /// The [publicExponent] must be given as [BigInt]. Currently, this package
  /// has opted to only support `3` and `65537` as [publicExponent], these are
  /// also the only values [supported by Chrome][chrome-src]. To generate RSA
  /// keys with a different [publicExponent] use a different package for key
  /// generation.
  /// It is common to use `65537` as [publicExponent],
  /// see [Wikipedia on RSA][wikipedia-rsa] for an explanation of
  /// [publicExponent] (and RSA in general).
  ///
  /// The hash algorithm to be used is specified by [hash]. Be ware that
  /// use of [Hash.sha1] is discouraged.
  ///
  /// [chrome-src]: https://chromium.googlesource.com/chromium/src/+/43d62c50b705f88c67b14539e91fd8fd017f70c4/components/webcrypto/algorithms/rsa.cc#286
  /// [keylength]: https://www.keylength.com/en/
  /// [nist-sp]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf
  /// [wikipedia-rsa]: https://en.wikipedia.org/wiki/RSA_(cryptosystem)
  /// {@endtemplate}
  ///
  /// **Example**
  /// ```dart
  /// import 'dart:convert' show utf8;
  /// import 'package:webcrypto/webcrypto.dart';
  /// import 'package:pem/pem.dart';
  ///
  /// // Generate a key-pair.
  /// final keyPair = await RsassaPkcs1V15PrivateKey.generateKey(
  ///   4096,
  ///   BigInt.from(65537),
  ///   Hash.sha256,
  /// );
  ///
  /// // Export public, so Alice can use it later.
  /// final spkiPublicKey = await keyPair.publicKey.exportSpkiKey();
  /// final pemPublicKey = PemCodec(PemLabel.publicKey).encode(spkiPublicKey);
  /// print(pemPublicKey); // print key in PEM format: -----BEGIN PUBLIC KEY....
  ///
  /// // Sign a message for Alice.
  /// final message = 'Hi Alice';
  /// final signature = await keyPair.privateKey.signBytes(
  ///   utf8.encode(message),
  /// );
  ///
  /// // On the other side of the world, Alice has written down the pemPublicKey
  /// // on a trusted piece of paper, but receives the message and signature
  /// // from an untrusted source (thus, desires to verify the signature).
  /// final publicKey = await RsassaPkcs1V15PublicKey.importSpkiKey(
  ///   PemCodec(PemLabel.publicKey).decode(pemPublicKey),
  ///   Hash.sha256,
  /// );
  /// final isValid = await publicKey.verifyBytes(
  ///   signature,
  ///   utf8.encode(message),
  /// );
  /// if (isValid) {
  ///   print('Authentic message from Bob: $message');
  /// }
  /// ```
  static Future<KeyPair<RsassaPkcs1V15PrivateKey, RsassaPkcs1V15PublicKey>>
      generateKey(
    int modulusLength,
    BigInt publicExponent,
    Hash hash,
  ) {
    return impl.rsassaPkcs1V15PrivateKey_generateKey(
      modulusLength,
      publicExponent,
      hash,
    );
  }

  /// Sign [data] with this RSASSA-PKCS1-v1_5 private key.
  ///
  /// Returns a signature as a list of raw bytes. This uses the [Hash]
  /// specified when the key was generated or imported.
  ///
  /// **Example**
  /// ```dart
  /// import 'dart:convert' show utf8, base64;
  /// import 'package:webcrypto/webcrypto.dart';
  /// import 'package:pem/pem.dart';
  ///
  /// // Read prviate key data from PEM encoded block. This will remove the
  /// // '----BEGIN...' padding, decode base64 and return encoded bytes.
  /// List<int> keyData = PemCodec(PemLabel.privateKey).decode("""
  ///   -----BEGIN PRIVATE KEY-----
  ///   MIGEAgEAMBAGByqG...
  ///   -----END PRIVATE KEY-----
  /// """);
  ///
  /// // Import private key from binary PEM decoded data.
  /// final privatKey = await RsassaPkcs1V15PrivateKey.importPkcs8Key(
  ///   keyData,
  ///   Hash.sha256,
  /// );
  ///
  /// // Create a signature for UTF-8 encoded message
  /// final message = 'hello world';
  /// final signature = await privateKey.signBytes(utf8.encode(message));
  ///
  /// print('signature: ${base64.encode(signature)}');
  /// ```
  Future<Uint8List> signBytes(List<int> data);

  /// Sign [data] with this RSASSA-PKCS1-v1_5 private key.
  ///
  /// Returns a signature as a list of raw bytes. This uses the [Hash]
  /// specified when the key was generated or imported.
  ///
  /// **Example**
  /// ```dart
  /// import 'dart:convert' show utf8, base64;
  /// import 'package:webcrypto/webcrypto.dart';
  /// import 'package:pem/pem.dart';
  ///
  /// // Read prviate key data from PEM encoded block. This will remove the
  /// // '----BEGIN...' padding, decode base64 and return encoded bytes.
  /// List<int> keyData = PemCodec(PemLabel.privateKey).decode("""
  ///   -----BEGIN PRIVATE KEY-----
  ///   MIGEAgEAMBAGByqG...
  ///   -----END PRIVATE KEY-----
  /// """);
  ///
  /// // Import private key from binary PEM decoded data.
  /// final privatKey = await RsassaPkcs1V15PrivateKey.importPkcs8Key(
  ///   keyData,
  ///   Hash.sha256,
  /// );
  ///
  /// // Create a signature for UTF-8 encoded message
  /// final message = 'hello world';
  /// final signature = await privateKey.signStream(Stream.fromIterable([
  ///   utf8.encode(message),
  /// ]));
  ///
  /// print('signature: ${base64.encode(signature)}');
  /// ```
  Future<Uint8List> signStream(Stream<List<int>> data);

  /// Export this RSASSA-PKCS1-v1_5 private key in PKCS #8 format.
  ///
  /// Returns the DER encoding of the _PrivateKeyInfo structure_ specified in
  /// [RFC 5208][1] as a list of bytes.
  ///
  /// **Example**
  /// ```dart
  /// import 'package:webcrypto/webcrypto.dart';
  /// import 'package:pem/pem.dart';
  ///
  /// // Generate a key-pair.
  /// final keyPair = await RsassaPkcs1V15PrivateKey.generateKey(
  ///   4096,
  ///   BigInt.from(65537),
  ///   Hash.sha256,
  /// );
  ///
  /// // Export the private key.
  /// final rawPrivateKey = await keypair.privateKey.exportPkcs8Key();
  ///
  /// // Private keys are often encoded as PEM.
  /// // This encodes the key in base64 and wraps it with:
  /// // '-----BEGIN PRIVATE KEY----'...
  /// print(PemCodec(PemLabel.privateKey).encode(rawPrivateKey));
  /// ```
  ///
  /// [1]: https://tools.ietf.org/html/rfc5208
  Future<Uint8List> exportPkcs8Key();

  /// Export RSASSA-PKCS1-v1_5 private key in [JSON Web Key][1] format.
  ///
  /// {@template exportJsonWebKey:returns}
  /// The output will be given as [Map], [String], [List] the same way
  /// [jsonDecode] from `dart:convert` represents decoded JSON values.
  /// {@endtemplate}
  ///
  /// **Example**
  /// ```dart
  /// import 'package:webcrypto/webcrypto.dart';
  /// import 'dart:convert' show jsonEncode;
  ///
  /// // Generate a key-pair.
  /// final keyPair = await RsassaPkcs1V15PrivateKey.generateKey(
  ///   4096,
  ///   BigInt.from(65537),
  ///   Hash.sha256,
  /// );
  ///
  /// // Export the private key.
  /// final jwk = await keypair.privateKey.exportJsonWebKey();
  ///
  /// // The Map returned by `exportJsonWebKey()` can be converted to JSON with
  /// // `jsonEncode` from `dart:convert`, this will print something like:
  /// // {"kty": "RSA", "alg": "RS256", ...}
  /// print(jsonEncode(jwk));
  /// ```
  ///
  /// [1]: https://tools.ietf.org/html/rfc7517
  Future<Map<String, dynamic>> exportJsonWebKey();
}

/// RSASSA-PKCS1-v1_5 public key for signing messages.
///
/// An [RsassaPkcs1V15PublicKey] instance hold a public RSA key for verification
/// of signatures following the RSASSA-PKCS1-v1_5 scheme as specified
/// in [RFC 3447][1].
///
/// An [RsassaPkcs1V15PublicKey] can be imported from:
///  * [SPKI][2] format using [RsassaPkcs1V15PublicKey.importSpkiKey], and,
///  * [JWK][3] format using [RsassaPkcs1V15PublicKey.importJsonWebKey].
///
/// A public-private [KeyPair] consisting of a [RsassaPkcs1V15PublicKey] and a
/// [RsassaPkcs1V15PrivateKey] can be generated using
/// [RsassaPkcs1V15PrivateKey.generateKey].
///
/// {@macro RSASSA-PKCS1-v1_5-Example:generate-sign-verify}
///
/// [1]: https://tools.ietf.org/html/rfc3447
/// [2]: https://tools.ietf.org/html/rfc5280
/// [3]: https://tools.ietf.org/html/rfc7517
@sealed
abstract class RsassaPkcs1V15PublicKey {
  RsassaPkcs1V15PublicKey._(); // keep the constructor private.

  /// Import RSASSA-PKCS1-v1_5 public key in SPKI format.
  ///
  /// Creates an [RsassaPkcs1V15PublicKey] from [keyData] given as the DER
  /// encoding of the _SubjectPublicKeyInfo structure_ specified in
  /// [RFC 5280][1]. The hash algorithm to be used is specified by [hash].
  ///
  /// {@macro RSA-importKey:throws-FormatException-if-KeyData}
  ///
  /// **Example**
  /// ```dart
  /// import 'package:webcrypto/webcrypto.dart';
  /// import 'package:pem/pem.dart';
  ///
  /// // Read key data from PEM encoded block. This will remove the
  /// // '----BEGIN...' padding, decode base64 and return encoded bytes.
  /// List<int> keyData = PemCodec(PemLabel.publicKey).decode("""
  ///   -----BEGIN PUBLIC KEY-----
  ///   MIGEAgEAMBAGByqG...
  ///   -----END PUBLIC KEY-----
  /// """);
  ///
  /// // Import public key from binary PEM decoded data.
  /// final publicKey = await RsassaPkcs1V15PublicKey.importSpkiKey(
  ///   keyData,
  ///   Hash.sha256,
  /// );
  ///
  /// // Export the key again (print it in same format as it was given).
  /// List<int> rawKeyData = await publicKey.exportSpkiKey();
  /// print(PemCodec(PemLabel.publicKey).encode(rawKeyData));
  /// ```
  ///
  /// [1]: https://tools.ietf.org/html/rfc5280
  static Future<RsassaPkcs1V15PublicKey> importSpkiKey(
    List<int> keyData,
    Hash hash,
  ) {
    return impl.rsassaPkcs1V15PublicKey_importSpkiKey(keyData, hash);
  }

  /// Import RSASSA-PKCS1-v1_5 public key in [JSON Web Key][1] format.
  ///
  /// {@macro importJsonWebKey:jwk}
  ///
  /// JSON Web Keys imported using [RsassaPkcs1V15PublicKey.importJsonWebKey]
  /// must have `"kty": "RSA"`, and the [hash] given must match the hash
  /// algorithm implied by the `"alg"` property of the imported [jwk].
  ///
  /// {@macro RSASSA-PKCS1-v1_5-importJsonWebKey:jwk-alg-list}
  ///
  /// {@macro importJsonWebKey:throws-FormatException-if-jwk}
  ///
  /// **Example**
  /// ```dart
  /// import 'package:webcrypto/webcrypto.dart';
  /// import 'dart:convert' show jsonEncode, jsonDecode;
  ///
  /// // JSON Web Key as a string containing JSON.
  /// final jwk = '{"kty": "RSA", "alg": "RS256", ...}';
  ///
  /// // Import public key from decoded JSON.
  /// final publicKey = await RsassaPkcs1V15PublicKey.importJsonWebKey(
  ///   jsonDecode(jwk),
  ///   Hash.sha256, // Must match the hash used the JWK key "alg"
  /// );
  ///
  /// // Export the key (print it in same format as it was given).
  /// Map<String, dynamic> keyData = await publicKey.exportJsonWebKey();
  /// print(jsonEncode(keyData));
  /// ```
  ///
  /// {@macro RSA-importJsonWebKey:use-key_ops}
  ///
  /// [1]: https://tools.ietf.org/html/rfc7517
  static Future<RsassaPkcs1V15PublicKey> importJsonWebKey(
    Map<String, dynamic> jwk,
    Hash hash,
  ) {
    return impl.rsassaPkcs1V15PublicKey_importJsonWebKey(jwk, hash);
  }

  /// Verify [signature] of [data] using this RSASSA-PKCS1-v1_5 public key.
  ///
  /// Returns `true` if the signature was made the private key matching this
  /// public key. This uses the [Hash] specified when the key was
  /// generated or imported.
  ///
  /// **Example**
  /// ```dart
  /// import 'dart:convert' show utf8;
  /// import 'package:webcrypto/webcrypto.dart';
  ///
  /// // Generate a key-pair.
  /// final keyPair = await RsassaPkcs1V15PrivateKey.generateKey(
  ///   4096,
  ///   BigInt.from(65537),
  ///   Hash.sha256,
  /// );
  ///
  /// // Using privateKey Bob can sign a message for Alice.
  /// final message = 'Hi Alice';
  /// final signature = await keyPair.privateKey.signBytes(utf8.encode(message));
  ///
  /// // Given publicKey and signature Alice can verify the message from Bob.
  /// final isValid = await keypair.publicKey.verifyBytes(
  ///   signature,
  ///   utf8.encode(message),
  /// );
  /// if (isValid) {
  ///   print('Authentic message from Bob: $message');
  /// }
  /// ```
  Future<bool> verifyBytes(List<int> signature, List<int> data);

  /// Verify [signature] of [data] using this RSASSA-PKCS1-v1_5 public key.
  ///
  /// Returns `true` if the signature was made the private key matching this
  /// public key. This uses the [Hash] specified when the key was
  /// generated or imported.
  ///
  /// **Example**
  /// ```dart
  /// import 'dart:convert' show utf8;
  /// import 'package:webcrypto/webcrypto.dart';
  ///
  /// // Generate a key-pair.
  /// final keyPair = await RsassaPkcs1V15PrivateKey.generateKey(
  ///   4096,
  ///   BigInt.from(65537),
  ///   Hash.sha256,
  /// );
  ///
  /// // Using privateKey Bob can sign a message for Alice.
  /// final message = 'Hi Alice';
  /// final signature = await keyPair.privateKey.signBytes(utf8.encode(message));
  ///
  /// // Given publicKey and signature Alice can verify the message from Bob.
  /// final isValid = await keypair.publicKey.verifyStream(
  ///   signature,
  ///   Stream.fromIterable([utf8.encode(message)]),
  /// );
  /// if (isValid) {
  ///   print('Authentic message from Bob: $message');
  /// }
  /// ```
  Future<bool> verifyStream(List<int> signature, Stream<List<int>> data);

  /// Export RSASSA-PKCS1-v1_5 public key in SPKI format.
  ///
  /// Returns the DER encoding of the _SubjectPublicKeyInfo structure_ specified
  /// in [RFC 5280][1] as a list of bytes.
  ///
  /// **Example**
  /// ```dart
  /// import 'package:webcrypto/webcrypto.dart';
  /// import 'package:pem/pem.dart';
  ///
  /// // Generate a key-pair.
  /// final keyPair = await RsassaPkcs1V15PrivateKey.generateKey(
  ///   4096,
  ///   BigInt.from(65537),
  ///   Hash.sha256,
  /// );
  ///
  /// // Export the public key.
  /// final rawPublicKey = await keyPair.publicKey.exportSpkiKey();
  ///
  /// // Public keys are often encoded as PEM.
  /// // This encode the key in base64 and wraps it with:
  /// // '-----BEGIN PUBLIC KEY-----'...
  /// print(PemCodec(PemLabel.publicKey).encode(rawPublicKey));
  /// ```
  ///
  /// [1]: https://tools.ietf.org/html/rfc5280
  Future<Uint8List> exportSpkiKey();

  /// Export RSASSA-PKCS1-v1_5 public key in [JSON Web Key][1] format.
  ///
  /// {@macro exportJsonWebKey:returns}
  ///
  /// **Example**
  /// ```dart
  /// import 'package:webcrypto/webcrypto.dart';
  /// import 'dart:convert' show jsonEncode;
  ///
  /// // Generate a key-pair.
  /// final keyPair = await RsassaPkcs1V15PrivateKey.generateKey(
  ///   4096,
  ///   BigInt.from(65537),
  ///   Hash.sha256,
  /// );
  ///
  /// // Export the public key.
  /// final jwk = await keypair.publicKey.exportJsonWebKey();
  ///
  /// // The Map returned by `exportJsonWebKey()` can be converted to JSON with
  /// // `jsonEncode` from `dart:convert`, this will print something like:
  /// // {"kty": "RSA", "alg": "RS256", ...}
  /// print(jsonEncode(jwk));
  /// ```
  ///
  /// [1]: https://tools.ietf.org/html/rfc7517
  Future<Map<String, dynamic>> exportJsonWebKey();
}
