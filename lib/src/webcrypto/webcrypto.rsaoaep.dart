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

/// RSAES-OAEP private key for decryption of messages.
///
/// An [RsaOaepPrivateKey] instance holds a private RSA key for decrypting
/// messages using the RSAES-OAEP scheme as specified in [RFC 3447][1].
///
/// An [RsaOaepPrivateKey] can be imported from:
///  * [PKCS #8][2] format using [RsaOaepPrivateKey.importPkcs8Key], and,
///  * [JWK][3] format using [RsaOaepPrivateKey.importJsonWebKey].
///
/// A public-private [KeyPair] consisting of a [RsaOaepPublicKey] and a
/// [RsaOaepPrivateKey] can be generated using [RsaOaepPrivateKey.generateKey].
///
/// {@template RSAES-OAEP-Example:generate-encrypt-verify}
/// **Example**
/// ```dart
/// import 'dart:typed_data' show Uint8List;
/// import 'dart:convert' show utf8;
/// import 'package:webcrypto/webcrypto.dart';
///
/// // Generate a public / private key-pair.
/// final keyPair = await RsaOaepPrivateKey.generateKey(
///   4096,
///   BigInt.from(65537),
///   Hash.sha256,
/// );
///
/// // Generate a 256 bit symmetric key
/// final secretKeyToBeShared = await AesGcmSecretKey.generateKey(256);
///
/// // Using publicKey Bob can encrypt secretKeyToBeShared, such that it can
/// // only be decrypted with the private key.
/// final encryptedRawKey = await keyPair.publicKey.encryptBytes(
///   await secretKeyToBeShared.exportRawKey(),
///   label: 'shared-key',
/// );
///
/// // Given privateKey and encryptedRawKey Alice can decrypt the shared key.
/// final sharedRawSecretKey = await keypair.privateKey.decryptBytes(
///   encryptedRawKey,
///   label: 'shared-key',
/// );
/// final sharedSecretKey = await AesGcmSecretKey.importRaw(sharedRawSecretKey);
/// // Now both Alice and Bob share a secret key.
/// ```
/// {@endtemplate}
///
/// {@template RSAES-OAEP-message-size-limit}
/// The size of the message to be encrypted is limited to
/// `message.length <= (modulusLength - 2 * hashLength - 2) / 8`.
/// Thus, [RsaOaepPublicKey.encryptBytes] is usually only used to encrypt the
/// key for symmetric cipher like [AesCbcSecretKey], [AesCtrSecretKey] or
/// [AesGcmSecretKey], after which the symmetric cipher can be used
/// encrypt/decrypt larger messages.
/// {@endtemplate}
///
/// [1]: https://tools.ietf.org/html/rfc3447
/// [2]: https://tools.ietf.org/html/rfc5208
/// [3]: https://tools.ietf.org/html/rfc7517
@sealed
abstract class RsaOaepPrivateKey {
  RsaOaepPrivateKey._(); // keep the constructor private.

  /// Import RSAES-OAEP private key in PKCS #8 format.
  ///
  /// Creates an [RsaOaepPrivateKey] from [keyData] given as the DER
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
  /// final privateKey = await RsaOaepPrivateKey.importPkcs8Key(
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
  static Future<RsaOaepPrivateKey> importPkcs8Key(
    List<int> keyData,
    Hash hash,
  ) {
    return impl.rsaOaepPrivateKey_importPkcs8Key(keyData, hash);
  }

  /// Import RSAES-OAEP private key in [JSON Web Key][1] format.
  ///
  /// {@macro importJsonWebKey:jwk}
  ///
  /// JSON Web Keys imported using [RsaOaepPrivateKey.importJsonWebKey]
  /// must have `"kty": "RSA"`, and the [hash] given must match the hash
  /// algorithm implied by the `"alg"` property of the imported [jwk].
  ///
  /// {@template RSAES-OAEP-importJsonWebKey:jwk-alg-list}
  /// For importing a JWK with:
  ///  * `"alg": "RSA-OAEP"` use [Hash.sha1] (**SHA-1 is weak**),
  ///  * `"alg": "RSA-OAEP-256"` use [Hash.sha256],
  ///  * `"alg": "RSA-OAEP-384"` use [Hash.sha384], and,
  ///  * `"alg": "RSA-OAEP-512"` use [Hash.sha512].
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
  /// final jwk = '{"kty": "RSA", "alg": "RSA-OAEP-256", ...}';
  ///
  /// // Import private key from decoded JSON.
  /// final privateKey = await RsaOaepPrivateKey.importJsonWebKey(
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
  static Future<RsaOaepPrivateKey> importJsonWebKey(
    Map<String, dynamic> jwk,
    Hash hash,
  ) {
    return impl.rsaOaepPrivateKey_importJsonWebKey(jwk, hash);
  }

  /// Generate an RSAES-OAEP public/private key-pair.
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
  /// final keyPair = await RsaOaepPrivateKey.generateKey(
  ///   4096,
  ///   BigInt.from(65537),
  ///   Hash.sha256,
  /// );
  ///
  /// // Export public, so Bob can use it
  /// final spkiPublicKey = await keyPair.publicKey.exportSpkiKey();
  /// final pemPublicKey = PemCodec(PemLabel.publicKey).encode(spkiPublicKey);
  /// print(pemPublicKey); // print key in PEM format: -----BEGIN PUBLIC KEY....
  /// // Alice sends pemPublicKey to Bob
  ///
  /// // Bob can generate a 256 bit symmetric secret key
  /// final secretKeyToBeShared = await AesGcmSecretKey.generateKey(256);
  ///
  /// // Using publicKey Bob can encrypt secretKeyToBeShared, such that it can
  /// // only be decrypted with the private key.
  /// final publicKey = RsaOaepPublicKey.importSpki(
  ///   PemCodec(PemLabel.publicKey).decode(pemPublicKey),
  ///   Hash.sha256,
  /// )
  /// final encryptedRawKey = await publicKey.encryptBytes(
  ///   await secretKeyToBeShared.exportRawKey(),
  ///   label: 'shared-key',
  /// );
  /// // Bob sends Alice: encryptedRawKey
  ///
  /// // Given privateKey and encryptedRawKey Alice can decrypt the shared key.
  /// final sharedRawSecretKey = await keypair.privateKey.decryptBytes(
  ///   encryptedRawKey,
  ///   label: 'shared-key',
  /// );
  /// final sharedSecretKey = await AesGcmSecretKey.importRaw(
  ///   sharedRawSecretKey,
  /// );
  /// // Now both Alice and Bob share a secret key.
  /// ```
  static Future<KeyPair<RsaOaepPrivateKey, RsaOaepPublicKey>> generateKey(
    int modulusLength,
    BigInt publicExponent,
    Hash hash,
  ) {
    return impl.rsaOaepPrivateKey_generateKey(
      modulusLength,
      publicExponent,
      hash,
    );
  }

  /// Decrypt [data] encrypted with [RsaOaepPublicKey.encryptBytes] from the
  /// matching public key.
  ///
  /// If [label] was specified when [data] was encrypted, then the same [label]
  /// must be specified during decryption. See [RsaOaepPublicKey.encryptBytes]
  /// for more information about usages for [label].
  ///
  /// **Example**
  /// ```dart
  /// import 'dart:convert' show utf8;
  /// import 'package:webcrypto/webcrypto.dart';
  /// import 'package:pem/pem.dart';
  ///
  /// // Generate a key-pair.
  /// final keyPair = await RsaOaepPrivateKey.generateKey(
  ///   4096,
  ///   BigInt.from(65537),
  ///   Hash.sha256,
  /// );
  /// // Alice sends keyPair.publicKey to Bob
  ///
  /// // Bob can generate a 256 bit symmetric secret key
  /// final secretKeyToBeShared = await AesGcmSecretKey.generateKey(256);
  ///
  /// // Using the public key Bob can encrypt secretKeyToBeShared, such that it
  /// // can only be decrypted with the private key.
  /// final encryptedRawKey = await keyPair.publicKey.encryptBytes(
  ///   await secretKeyToBeShared.exportRawKey(),
  /// );
  /// // Bob sends Alice: encryptedRawKey
  ///
  /// // Given privateKey and encryptedRawKey Alice can decrypt the shared key.
  /// final sharedRawSecretKey = await keypair.privateKey.decryptBytes(
  ///   encryptedRawKey,
  /// );
  /// final sharedSecretKey = await AesGcmSecretKey.importRaw(
  ///   sharedRawSecretKey,
  /// );
  /// // Now both Alice and Bob share a secret key.
  /// ```
  Future<Uint8List> decryptBytes(List<int> data, {List<int>? label});

  /// Export this RSAES-OAEP private key in PKCS #8 format.
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
  /// final keyPair = await RsaOaepPrivateKey.generateKey(
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

  /// Export RSAES-OAEP private key in [JSON Web Key][1] format.
  ///
  /// {@macro exportJsonWebKey:returns}
  ///
  /// **Example**
  /// ```dart
  /// import 'package:webcrypto/webcrypto.dart';
  /// import 'dart:convert' show jsonEncode;
  ///
  /// // Generate a key-pair.
  /// final keyPair = await RsaOaepPrivateKey.generateKey(
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
  /// // {"kty": "RSA", "alg": "RSA-OAEP-256", ...}
  /// print(jsonEncode(jwk));
  /// ```
  ///
  /// [1]: https://tools.ietf.org/html/rfc7517
  Future<Map<String, dynamic>> exportJsonWebKey();
}

/// RSAES-OAEP public key for decryption of messages.
///
/// An [RsaOaepPublicKey] instance holds a public RSA key for encrypting
/// messages using the RSAES-OAEP scheme as specified in [RFC 3447][1].
///
/// An [RsaOaepPublicKey] can be imported from:
///  * [SPKI][2] format using [RsaOaepPublicKey.exportSpkiKey], and,
///  * [JWK][3] format using [RsaOaepPublicKey.importJsonWebKey].
///
/// A public-private [KeyPair] consisting of a [RsaOaepPublicKey] and a
/// [RsaOaepPrivateKey] can be generated using [RsaOaepPrivateKey.generateKey].
///
/// {@macro RSAES-OAEP-Example:generate-encrypt-verify}
///
/// {@macro RSAES-OAEP-message-size-limit}
///
/// [1]: https://tools.ietf.org/html/rfc3447
/// [2]: https://tools.ietf.org/html/rfc5280
/// [3]: https://tools.ietf.org/html/rfc7517
@sealed
abstract class RsaOaepPublicKey {
  RsaOaepPublicKey._(); // keep the constructor private.

  /// Import RSAES-OAEP public key in SPKI format.
  ///
  /// Creates an [RsaOaepPublicKey] from [keyData] given as the DER
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
  /// final publicKey = await RsaOaepPublicKey.importSpkiKey(
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
  static Future<RsaOaepPublicKey> importSpkiKey(
    List<int> keyData,
    Hash hash,
  ) {
    return impl.rsaOaepPublicKey_importSpkiKey(keyData, hash);
  }

  /// Import RSAES-OAEP public key in [JSON Web Key][1] format.
  ///
  /// {@macro importJsonWebKey:jwk}
  ///
  /// JSON Web Keys imported using [RsaOaepPublicKey.importJsonWebKey]
  /// must have `"kty": "RSA"`, and the [hash] given must match the hash
  /// algorithm implied by the `"alg"` property of the imported [jwk].
  ///
  /// {@macro RSAES-OAEP-importJsonWebKey:jwk-alg-list}
  ///
  /// {@macro importJsonWebKey:throws-FormatException-if-jwk}
  ///
  /// **Example**
  /// ```dart
  /// import 'package:webcrypto/webcrypto.dart';
  /// import 'dart:convert' show jsonEncode, jsonDecode;
  ///
  /// // JSON Web Key as a string containing JSON.
  /// final jwk = '{"kty": "RSA", "alg": "RSA-OAEP-256", ...}';
  ///
  /// // Import public key from decoded JSON.
  /// final publicKey = await RsaOaepPublicKey.importJsonWebKey(
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
  static Future<RsaOaepPublicKey> importJsonWebKey(
    Map<String, dynamic> jwk,
    Hash hash,
  ) {
    return impl.rsaOaepPublicKey_importJsonWebKey(jwk, hash);
  }

  /// Encrypt [data] such that it can only be decrypted with
  /// [RsaOaepPrivateKey.decryptBytes] from the matching private key.
  ///
  /// The optional [label] may be used to provide arbitrary data that will not
  /// be encrypted, but instead specifies important context for the [data].
  /// If an [RsaOaepPublicKey] is used to encrypt multiple kinds of data,
  /// then using a unique [label] for each _kind of data_ ensures that
  /// data encrypted for one purpose cannot be reused for another purpose by
  /// an adversary.
  /// For further discussion of labels, see
  /// [section 2.1.4 of "A Proposal for an ISO Standard for Public Key Encryption"][1].
  ///
  /// The size of the [data] to be encrypted is limited to
  /// `data.length <= (modulusLength - 2 * hashLength - 2) / 8`, where
  /// `hashLength` and `modulusLength` are given in bits.
  /// For example, a 2048 bit RSA key with [Hash.sha256] cannot encrypt messages
  /// larger than 191 bytes.
  /// For this reason, RSAES-OAEP is often used to encrypt/decrypt a random
  /// one-time key for a symmetric cipher like [AesCbcSecretKey],
  /// [AesCtrSecretKey] or [AesGcmSecretKey], after which the symmetric cipher
  /// is used to encrypt/decrypt larger messages.
  ///
  /// **Example**
  /// ```dart
  /// import 'dart:convert' show utf8;
  /// import 'package:webcrypto/webcrypto.dart';
  /// import 'package:pem/pem.dart';
  ///
  /// // Generate a key-pair.
  /// final keyPair = await RsaOaepPrivateKey.generateKey(
  ///   4096,
  ///   BigInt.from(65537),
  ///   Hash.sha256,
  /// );
  /// // Alice sends keyPair.publicKey to Bob
  ///
  /// // Bob can generate a 256 bit symmetric secret key
  /// final secretKeyToBeShared = await AesGcmSecretKey.generateKey(256);
  ///
  /// // Using the public key Bob can encrypt secretKeyToBeShared, such that it
  /// // can only be decrypted with the private key.
  /// final encryptedRawKey = await keyPair.publicKey.encryptBytes(
  ///   await secretKeyToBeShared.exportRawKey(),
  ///   label: 'shared-key-exchange',
  /// );
  /// // Bob sends Alice: encryptedRawKey
  ///
  /// // Given privateKey and encryptedRawKey Alice can decrypt the shared key.
  /// final sharedRawSecretKey = await keypair.privateKey.decryptBytes(
  ///   encryptedRawKey,
  ///   label: 'shared-key-exchange',
  /// );
  /// final sharedSecretKey = await AesGcmSecretKey.importRaw(
  ///   sharedRawSecretKey,
  /// );
  /// // Now both Alice and Bob share a secret key.
  /// ```
  ///
  /// [1]: https://www.shoup.net/papers/iso-2_1.pdf
  // Note: A decent explanation of the [label] is available in:
  // Section 2.1.4 of "A Proposal for an ISO Standard for Public Key Encryption"
  // Version 2.1, by Victor Shoup, 2001.
  // https://www.shoup.net/papers/iso-2_1.pdf
  //
  // See also documentation for crypto/rsa in golang:
  // https://pkg.go.dev/crypto/rsa#EncryptOAEP
  Future<Uint8List> encryptBytes(List<int> data, {List<int>? label});

  /// Export this RSAES-OAEP public key in SPKI format.
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
  /// final keyPair = await RsaOaepPrivateKey.generateKey(
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

  /// Export RSAES-OAEP public key in [JSON Web Key][1] format.
  ///
  /// {@macro exportJsonWebKey:returns}
  ///
  /// **Example**
  /// ```dart
  /// import 'package:webcrypto/webcrypto.dart';
  /// import 'dart:convert' show jsonEncode;
  ///
  /// // Generate a key-pair.
  /// final keyPair = await RsaOaepPrivateKey.generateKey(
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
  /// // {"kty": "RSA", "alg": "RSA-OAEP-256", ...}
  /// print(jsonEncode(jwk));
  /// ```
  ///
  /// [1]: https://tools.ietf.org/html/rfc7517
  Future<Map<String, dynamic>> exportJsonWebKey();
}
