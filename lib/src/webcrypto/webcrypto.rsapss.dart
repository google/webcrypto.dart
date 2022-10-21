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

/// RSASSA-PSS private key for signing messages.
///
/// An [RsaPssPrivateKey] instance holds a private RSA key for computing
/// signatures using the RSASSA-PSS scheme as specified in [RFC 3447][1].
///
/// An [RsaPssPrivateKey] can be imported from:
///  * [PKCS #8][2] format using [RsaPssPrivateKey.importPkcs8Key], and,
///  * [JWK][3] format using [RsaPssPrivateKey.importJsonWebKey].
///
/// A public-private [KeyPair] consisting of a [RsaPssPublicKey] and a
/// [RsaPssPrivateKey] can be generated using [RsaPssPrivateKey.generateKey].
///
/// {@template RSASSA-PSS-Example:generate-sign-verify}
/// **Example**
/// ```dart
/// import 'dart:convert' show utf8;
/// import 'package:webcrypto/webcrypto.dart';
///
/// // Generate a key-pair.
/// final keyPair = await RsaPssPrivateKey.generateKey(
///   4096,
///   BigInt.from(65537),
///   Hash.sha256,
/// );
///
/// // Use the same saltLength for signing and verifying
/// const saltLength = 256 / 8;
///
/// // Using privateKey Bob can sign a message for Alice.
/// final message = 'Hi Alice';
/// final signature = await keyPair.privateKey.signBytes(
///   utf8.encode(message),
///   saltLength,
/// );
///
/// // Given publicKey and signature Alice can verify the message from Bob.
/// final isValid = await keypair.publicKey.verifyBytes(
///   signature,
///   utf8.encode(message),
///   saltLength,
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
abstract class RsaPssPrivateKey {
  RsaPssPrivateKey._(); // keep the constructor private.

  /// Import RSASSA-PSS private key in PKCS #8 format.
  ///
  /// Creates an [RsaPssPrivateKey] from [keyData] given as the DER
  /// encoding of the _PrivateKeyInfo structure_ specified in [RFC 5208][1].
  /// The hash algorithm to be used is specified by [hash].
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
  /// List<int> keyData = PemCodec(PemLabel.privateKey).decode("""
  ///   -----BEGIN PRIVATE KEY-----
  ///   MIGEAgEAMBAGByqG...
  ///   -----END PRIVATE KEY-----
  /// """);
  ///
  /// // Import private key from binary PEM decoded data.
  /// final privateKey = await RsaPssPrivateKey.importPkcs8Key(
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
  static Future<RsaPssPrivateKey> importPkcs8Key(
    List<int> keyData,
    Hash hash,
  ) {
    return impl.rsaPssPrivateKey_importPkcs8Key(keyData, hash);
  }

  /// Import RSASSA-PSS private key in [JSON Web Key][1] format.
  ///
  /// {@macro importJsonWebKey:jwk}
  ///
  /// JSON Web Keys imported using [RsaPssPrivateKey.importJsonWebKey]
  /// must have `"kty": "RSA"`, and the [hash] given must match the hash
  /// algorithm implied by the `"alg"` property of the imported [jwk].
  ///
  /// {@template RSASSA-PSS-importJsonWebKey:jwk-alg-list}
  /// For importing a JWK with:
  ///  * `"alg": "PS1"` use [Hash.sha1] (**SHA-1 is weak**),
  ///  * `"alg": "PS256"` use [Hash.sha256],
  ///  * `"alg": "PS384"` use [Hash.sha384], and,
  ///  * `"alg": "PS512"` use [Hash.sha512].
  /// {@endtemplate}
  ///
  /// {@macro importJsonWebKey:throws-FormatException-if-jwk}
  ///
  /// **Example**
  /// ```dart
  /// import 'package:webcrypto/webcrypto.dart';
  /// import 'dart:convert' show jsonEncode, jsonDecode;
  ///
  /// // JSON Web Key as a string containing JSON.
  /// final jwk = '{"kty": "RSA", "alg": "PS256", ...}';
  ///
  /// // Import private key from decoded JSON.
  /// final privateKey = await RsaPssPrivateKey.importJsonWebKey(
  ///   jsonDecode(jwk),
  ///   Hash.sha256, // Must match the hash used the JWK key "alg"
  /// );
  ///
  /// // Export the key (print it in same format as it was given).
  /// Map<String, dynamic> keyData = await privateKey.exportJsonWebKey();
  /// print(jsonEncode(keyData));
  /// ```
  ///
  /// {@macro RSA-importJsonWebKey:use-key_ops}
  ///
  /// [1]: https://tools.ietf.org/html/rfc7517
  static Future<RsaPssPrivateKey> importJsonWebKey(
    Map<String, dynamic> jwk,
    Hash hash,
  ) {
    return impl.rsaPssPrivateKey_importJsonWebKey(jwk, hash);
  }

  /// Generate an RSASSA-PSS public/private key-pair.
  ///
  /// {@macro RSA-generateKey:modulusLength-publicExponent-hash}
  ///
  /// **Example**
  /// ```dart
  /// import 'dart:convert' show utf8;
  /// import 'package:webcrypto/webcrypto.dart';
  /// import 'package:pem/pem.dart';
  ///
  /// // Generate a key-pair.
  /// final keyPair = await RsaPssPrivateKey.generateKey(
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
  /// // Use the same saltLength for signing and verifying
  /// const saltLength = 256 / 8;
  ///
  /// // Sign a message for Alice.
  /// final message = 'Hi Alice';
  /// final signature = await keyPair.privateKey.signBytes(
  ///   utf8.encode(message),
  ///   saltLength,
  /// );
  ///
  /// // On the other side of the world, Alice has written down the pemPublicKey
  /// // on a trusted piece of paper, but receives the message and signature
  /// // from an untrusted source (thus, desires to verify the signature).
  /// final publicKey = await RsaPssPublicKey.importSpkiKey(
  ///   PemCodec(PemLabel.publicKey).decode(pemPublicKey),
  ///   Hash.sha256,
  /// );
  /// final isValid = await publicKey.verifyBytes(
  ///   signature,
  ///   utf8.encode(message),
  ///   saltLength,
  /// );
  /// if (isValid) {
  ///   print('Authentic message from Bob: $message');
  /// }
  /// ```
  static Future<KeyPair<RsaPssPrivateKey, RsaPssPublicKey>> generateKey(
    int modulusLength,
    BigInt publicExponent,
    Hash hash,
  ) {
    return impl.rsaPssPrivateKey_generateKey(
      modulusLength,
      publicExponent,
      hash,
    );
  }

  /// Sign [data] with this RSASSA-PSS private key.
  ///
  /// Returns a signature as a list of raw bytes. This uses the [Hash]
  /// specified when the key was generated or imported. The length of the
  /// salt is specified in bytes using [saltLength].
  ///
  /// If the [saltLength] is zero the signature is deterministic.
  /// The [saltLength] is typically zero or length of the [Hash], for a
  /// discussion of appropriate values for [saltLength] see
  /// [RFC 3447 Section 9.1, Notes 4][1].
  ///
  /// When running in Safari/WebKit on Mac the [saltLength] is restricted to
  /// `0 <= saltLength <= hashLength` as the underlying cryptography libraries
  /// follow [FIPS 186-4, Section 5.5, Step (e)][2].
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
  /// final privatKey = await RsaPssPrivateKey.importPkcs8Key(
  ///   keyData,
  ///   Hash.sha256,
  /// );
  ///
  /// // Use the same salt for signing and verifying.
  /// // In this case we're using the length of the hash function, divided by 8
  /// // to as saltLength must be specified in bytes.
  /// const saltLength = 256 / 8;
  ///
  /// // Create a signature for UTF-8 encoded message
  /// final message = 'hello world';
  /// final signature = await privateKey.signBytes(
  ///   utf8.encode(message),
  ///   saltLength,
  /// );
  ///
  /// print('signature: ${base64.encode(signature)}');
  /// ```
  ///
  /// [1]: https://tools.ietf.org/html/rfc3447#section-9.1
  /// [2]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
  ///
  // Notes on saltLength for maintainers:
  // Source code for WebKit on Mac uses CommonCrypto:
  //   https://trac.webkit.org/browser/webkit/trunk/Source/WebCore/crypto/mac/CryptoAlgorithmRSA_PSSMac.cpp?rev=238754#L56
  // And CommonCrypto calls into corecrypto:
  //   https://opensource.apple.com/source/CommonCrypto/CommonCrypto-60165.120.1/lib/CommonRSACryptor.c.auto.html
  // which references FIPS 186-4, Section 5.5, Step (e):
  //   https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
  // limiting saltLength to 0 <= saltLength <= hashLength
  // Note: saltLength and hashLength is given in bytes.
  // Hence: hashLength = 256 / 8 is hash is sha256.
  //
  // It's unclear if a saltLength greater than hashLength has any practical
  // uses, we'd probably have to digg further into the literature to find source
  // we can quote. Most likely saltLength > hashLength is so obviously pointless
  // that nobody every considered proving or saying anything about it.
  // Which makes it hard for us to say that it's not useful.
  //
  // Note: Web Cryptography specification references RFC 3447, not FIPS 186-4.
  Future<Uint8List> signBytes(List<int> data, int saltLength);

  /// Sign [data] with this RSASSA-PSS private key.
  ///
  /// Returns a signature as a list of raw bytes. This uses the [Hash]
  /// specified when the key was generated or imported. The length of the
  /// salt is specified in bytes using [saltLength].
  ///
  /// If the [saltLength] is zero the signature is deterministic.
  /// The [saltLength] is typically zero or length of the [Hash], for a
  /// discussion of appropriate values for [saltLength] see
  /// [RFC 3447 Section 9.1, Notes 4][1].
  ///
  /// When running in Safari/WebKit on Mac the [saltLength] is restricted to
  /// `0 <= saltLength <= hashLength` as the underlying cryptography libraries
  /// follow [FIPS 186-4, Section 5.5, Step (e)][2].
  ///
  /// **Example**
  /// ```dart
  /// import 'dart:convert' show base64;
  /// import 'dart:io' show File;
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
  /// final privatKey = await RsaPssPrivateKey.importPkcs8Key(
  ///   keyData,
  ///   Hash.sha256,
  /// );
  ///
  /// // Use the same salt for signing and verifying.
  /// // In this case we're using the length of the hash function, divided by 8
  /// // to as saltLength must be specified in bytes.
  /// const saltLength = 256 / 8;
  ///
  /// // Create a signature for message read directly from file.
  /// final signature = await privateKey.signStream(
  ///   File('message.txt').openRead(),
  ///   saltLength,
  /// );
  ///
  /// print('signature: ${base64.encode(signature)}');
  /// ```
  ///
  /// [1]: https://tools.ietf.org/html/rfc3447#section-9.1
  /// [2]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
  Future<Uint8List> signStream(Stream<List<int>> data, int saltLength);

  /// Export this RSASSA-PSS private key in PKCS #8 format.
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
  /// final keyPair = await RsaPssPrivateKey.generateKey(
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

  /// Export RSASSA-PSS private key in [JSON Web Key][1] format.
  ///
  /// {@macro exportJsonWebKey:returns}
  ///
  /// **Example**
  /// ```dart
  /// import 'package:webcrypto/webcrypto.dart';
  /// import 'dart:convert' show jsonEncode;
  ///
  /// // Generate a key-pair.
  /// final keyPair = await RsaPssPrivateKey.generateKey(
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
  /// // {"kty": "RSA", "alg": "PS256", ...}
  /// print(jsonEncode(jwk));
  /// ```
  ///
  /// [1]: https://tools.ietf.org/html/rfc7517
  Future<Map<String, dynamic>> exportJsonWebKey();
}

/// RSASSA-PSS public key for verifying signatures.
///
/// An [RsaPssPublicKey] instance holds a public RSA key for verification of
/// signatures using the RSASSA-PSS scheme as specified in [RFC 3447][1].
///
/// An [RsaPssPublicKey] can be imported from:
///  * [SPKI][2] format using [RsaPssPublicKey.importSpkiKey], and,
///  * [JWK][3] format using [RsaPssPublicKey.importJsonWebKey].
///
/// A public-private [KeyPair] consisting of a [RsaPssPublicKey] and a
/// [RsaPssPrivateKey] can be generated using [RsaPssPrivateKey.generateKey].
///
/// {@macro RSASSA-PSS-Example:generate-sign-verify}
///
/// [1]: https://tools.ietf.org/html/rfc3447
/// [2]: https://tools.ietf.org/html/rfc5280
/// [3]: https://tools.ietf.org/html/rfc7517
@sealed
abstract class RsaPssPublicKey {
  RsaPssPublicKey._(); // keep the constructor private.

  /// Import RSASSA-PSS public key in SPKI format.
  ///
  /// Creates an [RsaPssPublicKey] from [keyData] given as the DER
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
  /// final publicKey = await RsaPssPublicKey.importSpkiKey(
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
  static Future<RsaPssPublicKey> importSpkiKey(
    List<int> keyData,
    Hash hash,
  ) {
    return impl.rsaPssPublicKey_importSpkiKey(keyData, hash);
  }

  /// Import RSASSA-PSS public key in [JSON Web Key][1] format.
  ///
  /// {@macro importJsonWebKey:jwk}
  ///
  /// JSON Web Keys imported using [RsaPssPublicKey.importJsonWebKey]
  /// must have `"kty": "RSA"`, and the [hash] given must match the hash
  /// algorithm implied by the `"alg"` property of the imported [jwk].
  ///
  /// {@macro RSASSA-PSS-importJsonWebKey:jwk-alg-list}
  ///
  /// {@macro importJsonWebKey:throws-FormatException-if-jwk}
  ///
  /// **Example**
  /// ```dart
  /// import 'package:webcrypto/webcrypto.dart';
  /// import 'dart:convert' show jsonEncode, jsonDecode;
  ///
  /// // JSON Web Key as a string containing JSON.
  /// final jwk = '{"kty": "RSA", "alg": "PS256", ...}';
  ///
  /// // Import public key from decoded JSON.
  /// final publicKey = await RsaPssPublicKey.importJsonWebKey(
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
  static Future<RsaPssPublicKey> importJsonWebKey(
    Map<String, dynamic> jwk,
    Hash hash,
  ) {
    return impl.rsaPssPublicKey_importJsonWebKey(jwk, hash);
  }

  /// Verify [signature] of [data] using this RSASSA-PSS public key.
  ///
  /// Returns `true` if the signature was made the private key matching this
  /// public key. This uses the [Hash] specified when the key was
  /// generated or imported. The length of the salt is specified in bytes
  /// using [saltLength].
  ///
  /// For limitations on [saltLength] see [RsaPssPrivateKey.signBytes].
  ///
  /// **Example**
  /// ```dart
  /// import 'dart:convert' show utf8;
  /// import 'package:webcrypto/webcrypto.dart';
  ///
  /// // Generate a key-pair.
  /// final keyPair = await RsaPssPrivateKey.generateKey(
  ///   4096,
  ///   BigInt.from(65537),
  ///   Hash.sha256,
  /// );
  ///
  /// // Use the same salt for signing and verifying.
  /// const saltLength = 256 / 8;
  ///
  /// // Using privateKey Bob can sign a message for Alice.
  /// final message = 'Hi Alice';
  /// final signature = await keyPair.privateKey.signBytes(
  ///   utf8.encode(message),
  ///   saltLength,
  /// );
  ///
  /// // Given publicKey and signature Alice can verify the message from Bob.
  /// final isValid = await keypair.publicKey.verifyBytes(
  ///   signature,
  ///   utf8.encode(message),
  ///   saltLength,
  /// );
  /// if (isValid) {
  ///   print('Authentic message from Bob: $message');
  /// }
  /// ```
  Future<bool> verifyBytes(
    List<int> signature,
    List<int> data,
    int saltLength,
  );

  /// Verify [signature] of [data] using this RSASSA-PSS public key.
  ///
  /// Returns `true` if the signature was made the private key matching this
  /// public key. This uses the [Hash] specified when the key was
  /// generated or imported. The length of the salt is specified in bytes
  /// using [saltLength].
  ///
  /// For limitations on [saltLength] see [RsaPssPrivateKey.signBytes].
  ///
  /// **Example**
  /// ```dart
  /// import 'dart:io' show File;
  /// import 'package:webcrypto/webcrypto.dart';
  ///
  /// // Generate a key-pair.
  /// final keyPair = await RsaPssPrivateKey.generateKey(
  ///   4096,
  ///   BigInt.from(65537),
  ///   Hash.sha256,
  /// );
  ///
  /// // Use the same salt for signing and verifying.
  /// const saltLength = 256 / 8;
  ///
  /// // Using privateKey Bob can sign a message for Alice.
  /// final signature = await keyPair.privateKey.signStream(
  ///   File('message.txt').openRead(), // read directly from file
  ///   saltLength,
  /// );
  ///
  /// // Given publicKey and signature Alice can verify the message from Bob.
  /// final isValid = await keypair.publicKey.verifyStream(
  ///   signature,
  ///   File('message.txt').openRead(), // read directly from file
  ///   saltLength,
  /// );
  /// if (isValid) {
  ///   print('Authentic message from Bob: $message');
  /// }
  /// ```
  Future<bool> verifyStream(
    List<int> signature,
    Stream<List<int>> data,
    int saltLength,
  );

  /// Export RSASSA-PSS public key in SPKI format.
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
  /// final keyPair = await RsaPssPrivateKey.generateKey(
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

  /// Export RSASSA-PSS public key in [JSON Web Key][1] format.
  ///
  /// {@macro exportJsonWebKey:returns}
  ///
  /// **Example**
  /// ```dart
  /// import 'package:webcrypto/webcrypto.dart';
  /// import 'dart:convert' show jsonEncode;
  ///
  /// // Generate a key-pair.
  /// final keyPair = await RsaPssPrivateKey.generateKey(
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
  /// // {"kty": "RSA", "alg": "PS256", ...}
  /// print(jsonEncode(jwk));
  /// ```
  ///
  /// [1]: https://tools.ietf.org/html/rfc7517
  Future<Map<String, dynamic>> exportJsonWebKey();
}
