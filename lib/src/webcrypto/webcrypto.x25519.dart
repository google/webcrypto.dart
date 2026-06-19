// Copyright 2025 Google LLC
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

/// X25519 private key for deriving a shared secret.
///
/// Elliptic Curve Diffie-Hellman (ECDH) is a key agreement protocol that allows
/// two parties to establish a shared secret over an insecure channel.
/// An [X25519PrivateKey] holds a private key that can be used to derive a
/// shared secret given the public key from a different key pair.
///
/// Instances of [X25519PrivateKey] can be imported from:
/// * PKCS8 Key using [X25519PrivateKey.importPkcs8Key], and,
/// * JSON Web Key using [X25519PrivateKey.importJsonWebKey].
///
/// A key pair can be generated using [X25519PrivateKey.generateKey].
///
/// {@template X25519PrivateKey:example}
/// **Example**
/// ```dart
/// import 'dart:convert';
/// import 'package:webcrypto/webcrypto.dart';
///
/// Future<void> main() async {
///   // Alice generates a key-pair
///   final kpA = await X25519PrivateKey.generateKey();
///
///   // Bob generates a key-pair
///   final kpB = await X25519PrivateKey.generateKey();
///
///   // Alice can make a shared secret using Bob's public key
///   final sharedSecretA = await kpA.privateKey.deriveBits(256, kpB.publicKey);
///
///   // Bob can make the same shared secret using Alice public key
///   final sharedSecretB = await kpB.privateKey.deriveBits(256, kpA.publicKey);
///
///   // Alice and Bob should have the same shared secret
///   assert(base64.encode(sharedSecretA) == base64.encode(sharedSecretB));
/// }
/// ```
/// {@endtemplate}
final class X25519PrivateKey {
  final X25519PrivateKeyImpl _impl;

  X25519PrivateKey._(this._impl); // keep the constructor private.

  /// Import [X25519PrivateKey] in the [PKCS #8][1] format.
  ///
  /// Creates an [X25519PrivateKey] from [keyData] given as the DER encodeding
  /// _PrivateKeyInfo structure_ specified in [RFC 5208][1].
  ///
  /// **Example**
  /// ```dart
  /// import 'package:pem/pem.dart';
  /// import 'package:webcrypto/webcrypto.dart';
  ///
  /// // Read key data from a PEM encoded block. This will remove the
  /// // the padding, decode base64 and return the encoded bytes.
  /// List<int> keyData = PemCodec(PemLabel.privateKey).decode('''
  ///   -----BEGIN PRIVATE KEY-----
  ///   MC4CAQAwBQYDK2VuBCI.....
  ///   -----END PRIVATE KEY-----
  ///   ''');
  ///
  ///
  /// Future<void> main() async {
  ///   // Import the Private Key from a Binary PEM decoded data.
  ///   final privateKey = await X25519PrivateKey.importPkcs8Key(keyData);
  ///
  ///  // Export the private key (print it in same format as it was given).
  ///  final exportedPkcs8Key = await privateKey.exportPkcs8Key();
  ///  print(PemCodec(PemLabel.privateKey).encode(exportedPkcs8Key));
  /// }
  /// ```
  ///
  /// [1]: https://datatracker.ietf.org/doc/html/rfc5208
  static Future<X25519PrivateKey> importPkcs8Key(List<int> keyData) async {
    final impl = await webCryptImpl.x25519PrivateKey.importPkcs8Key(keyData);
    return X25519PrivateKey._(impl);
  }

  /// Import X25519 private key in [JSON Web Key][1] format.
  ///
  /// {@macro importJsonWebKey:jwk}
  ///
  /// JSON Web Keys imported using [X25519PrivateKey.importJsonWebKey] must
  /// have the following parameters as described in [RFC 8037][2]:
  /// * `"kty"`: The key type must be `"OKP"`.
  /// * `"crv"`: The curve parameter must be `"X25519"`.
  /// * `"x"`: The x parameter must be present and contain the public key
  /// encoded as a [base64Url] encoded string.
  /// * `"d"`: The d parameter must be present for private keys and contain the
  /// private key encoded as a [base64Url] encoded string.
  ///
  /// **Example**
  /// ```dart
  /// import 'package:webcrypto/webcrypto.dart';
  ///
  /// // JSON Web Key as map representing the decoded JSON.
  /// final jwk = {
  ///   'kty': 'OKP',
  ///   'crv': 'X25519',
  ///   'x': 'coeKtJr7mBuIBzGjR_T4OFfuU3Sn85-frLUvxzg5320',
  ///   'd': '0iqe8CdaOI0uP_UG7wzEQanilG-UWWw4tuSeMKNXnKA',
  /// };
  ///
  /// Future<void> main() async {
  ///   // Import secret key from decoded JSON.
  ///   final jsonWebKey = await X25519PrivateKey.importJsonWebKey(jwk);
  ///
  ///   // Export the key (print it in same format as it was given).
  ///   final exportedJsonWebKey = await jsonWebKey.exportJsonWebKey();
  ///   print(exportedJsonWebKey);
  /// }
  /// ```
  ///
  /// [1]: https://tools.ietf.org/html/rfc7517
  /// [2]: https://datatracker.ietf.org/doc/html/rfc8037#section-2
  static Future<X25519PrivateKey> importJsonWebKey(
    Map<String, dynamic> jwk,
  ) async {
    final impl = await webCryptImpl.x25519PrivateKey.importJsonWebKey(jwk);
    return X25519PrivateKey._(impl);
  }

  /// Generate a new [X25519PrivateKey] and [X25519PublicKey] pair.
  ///
  /// **Example**
  /// ```dart
  /// import 'package:webcrypto/webcrypto.dart';
  ///
  /// Future<void> main() async {
  ///   // Generate a new X25519 key pair.
  ///   final keyPair = await X25519PrivateKey.generateKey();
  ///
  ///   // Export the private key.
  ///   final exportedPrivateKey = await keyPair.privateKey.exportJsonWebKey();
  ///   print(exportedPrivateKey);
  ///
  ///   // Export the public key.
  ///   final exportedPublicKey = await keyPair.publicKey.exportJsonWebKey();
  ///   print(exportedPublicKey);
  /// }
  /// ```
  ///
  static Future<KeyPair<X25519PrivateKey, X25519PublicKey>>
      generateKey() async {
    final (privateKeyImpl, publicKeyImpl) =
        await webCryptImpl.x25519PrivateKey.generateKey();

    final privateKey = X25519PrivateKey._(privateKeyImpl);
    final publicKey = X25519PublicKey._(publicKeyImpl);

    return (privateKey: privateKey, publicKey: publicKey);
  }

  /// Derive a shared secret from two X25519 key pairs using the private key
  /// from one pair and the public key from another.
  ///
  /// The shared secret is identical whether using A's private key and B's
  /// public key, or B's private key and A's public key, enabling secure key
  /// exchange between the two parties.
  ///
  /// [length] specifies the length of the derived secret in bits.
  /// [publicKey] is [X25519PublicKey] from the other party's X25519 key pair.
  ///
  /// Returns a [Uint8List] containing the derived shared secret.
  ///
  /// {@macro X25519PrivateKey:example}
  Future<Uint8List> deriveBits(int length, X25519PublicKey publicKey) async {
    final publicKeyImpl = publicKey._impl;
    return _impl.deriveBits(length, publicKeyImpl);
  }

  /// Export the [X25519PrivateKey] as a [PKCS #8][1] key.
  ///
  /// Returns the DER encoding of the _PrivateKeyInfo_ structure specified in
  /// [RFC 5208][1] as a list of bytes.
  ///
  /// **Example**
  /// ```dart
  /// import 'package:pem/pem.dart';
  /// import 'package:webcrypto/webcrypto.dart';
  ///
  /// Future<void> main() async {
  ///   // Generate a key-pair
  ///   final kp = await X25519PrivateKey.generateKey();
  ///
  ///   // Export the private key.
  ///   final exportedPkcs8Key = await kp.privateKey.exportPkcs8Key();
  ///
  ///   // Private keys are often encoded as PEM.
  ///   // This encodes the key in base64 and wraps it with:
  ///   // '-----BEGIN PRIVATE KEY----'...
  ///   print(PemCodec(PemLabel.privateKey).encode(exportedPkcs8Key));
  /// }
  /// ```
  /// [1]: https://datatracker.ietf.org/doc/html/rfc5208
  Future<Uint8List> exportPkcs8Key() => _impl.exportPkcs8Key();

  /// Export the [X25519PrivateKey] as a [JSON Web Key][1].
  ///
  /// {@macro exportJsonWebKey:returns}
  ///
  /// **Example**
  /// ```dart
  /// import 'dart:convert';
  /// import 'package:webcrypto/webcrypto.dart';
  ///
  /// Future<void> main() async {
  ///   // Alice generates a key-pair
  ///   final kpA = await X25519PrivateKey.generateKey();
  ///
  ///   // Export the private key as a JSON Web Key.
  ///   final exportedPrivateKey = await kpA.privateKey.exportJsonWebKey();
  ///
  ///   // The Map returned by `exportJsonWebKey()` can be converted to JSON
  ///   // with `jsonEncode` from `dart:convert`.
  ///   print(jsonEncode(exportedPrivateKey));
  /// }
  /// ```
  /// [1]: https://www.rfc-editor.org/rfc/rfc7518.html
  Future<Map<String, dynamic>> exportJsonWebKey() => _impl.exportJsonWebKey();
}

/// X25519 public key for deriving a shared secret.
///
/// An [X25519PublicKey] instance holds an X25519 public key for use with the
/// Elliptic Curve Diffie-Hellman (ECDH) key agreement protocol that allows
/// two parties to establish a shared secret over an insecure channel.
///
/// An [X25519PublicKey] can be imported from:
///  * Raw format using [X25519PublicKey.importRawKey],
///  * [SPKI][1] format using [X25519PublicKey.importSpkiKey], and,
///  * [JWK][2] format using [X25519PublicKey.importJsonWebKey].
///
/// A public-private [KeyPair] consisting of a [X25519PublicKey] and
/// [X25519PrivateKey] can be generated using [X25519PrivateKey.generateKey].
///
/// {@macro X25519PrivateKey:example}
///
/// [1]: https://tools.ietf.org/html/rfc5280
/// [2]: https://tools.ietf.org/html/rfc7517
final class X25519PublicKey {
  final X25519PublicKeyImpl _impl;

  X25519PublicKey._(this._impl); // keep the constructor private.

  static Future<X25519PublicKey> importRawKey(List<int> keyData) async {
    final impl = await webCryptImpl.x25519PublicKey.importRawKey(keyData);
    return X25519PublicKey._(impl);
  }

  static Future<X25519PublicKey> importSpkiKey(List<int> keyData) async {
    final impl = await webCryptImpl.x25519PublicKey.importSpkiKey(keyData);
    return X25519PublicKey._(impl);
  }

  /// Import X25519 public key in [JSON Web Key][1] format.
  ///
  /// {@macro importJsonWebKey:jwk}
  ///
  /// JSON Web Keys imported using [X25519PublicKey.importJsonWebKey] must
  /// have the following parameters as described in [RFC 8037][2]:
  /// * `"kty"`: The key type must be `"OKP"`.
  /// * `"crv"`: The curve parameter must be `"X25519"`.
  /// * `"x"`: The x parameter must be present and contain the public key
  /// encoded as a [base64Url] encoded string.
  ///
  /// **Example**
  /// ```dart
  /// import 'package:webcrypto/webcrypto.dart';
  ///
  /// // JSON Web Key as map representing the decoded JSON.
  /// final jwk = {
  ///   'kty': 'OKP',
  ///   'crv': 'X25519',
  ///   'x': 'coeKtJr7mBuIBzGjR_T4OFfuU3Sn85-frLUvxzg5320',
  /// };
  ///
  /// Future<void> main() async {
  ///   // Import the public key from decoded JSON.
  ///   final jsonWebKey = await X25519PublicKey.importJsonWebKey(jwk);
  ///
  ///   // Export the key (print it in same format as it was given).
  ///   final exportedJsonWebKey = await jsonWebKey.exportJsonWebKey();
  ///   print(exportedJsonWebKey);
  /// }
  /// ```
  ///
  /// [1]: https://tools.ietf.org/html/rfc7517
  /// [2]: https://datatracker.ietf.org/doc/html/rfc8037#section-2
  static Future<X25519PublicKey> importJsonWebKey(
    Map<String, dynamic> jwk,
  ) async {
    final impl = await webCryptImpl.x25519PublicKey.importJsonWebKey(jwk);
    return X25519PublicKey._(impl);
  }

  /// Export X25519 public key as a raw list of bytes.
  ///
  /// **Example**
  /// ```dart
  /// import 'package:webcrypto/webcrypto.dart';
  ///
  /// // Generate a key-pair.
  /// final keyPair = await X25519PrivateKey.generateKey();
  ///
  /// // Export the public key as raw bytes.
  /// final rawPublicKey = await keyPair.publicKey.exportRawKey();
  Future<Uint8List> exportRawKey() => _impl.exportRawKey();

  /// Export X25519 public key in SPKI format.
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
  /// final keyPair = await X25519PrivateKey.generateKey();
  ///
  /// // Export the public key.
  /// final spkiPublicKey = await keyPair.publicKey.exportSpkiKey();
  ///
  /// // Public keys are often encoded as PEM.
  /// // This encode the key in base64 and wraps it with:
  /// // '-----BEGIN PUBLIC KEY-----'...
  /// print(PemCodec(PemLabel.publicKey).encode(spkiPublicKey));
  /// ```
  ///
  /// [1]: https://tools.ietf.org/html/rfc5280
  Future<Uint8List> exportSpkiKey() => _impl.exportSpkiKey();

  /// Export the [X25519PublicKey] as a [JSON Web Key][1].
  ///
  /// {@macro exportJsonWebKey:returns}
  ///
  /// **Example**
  /// ```dart
  /// import 'dart:convert';
  /// import 'package:webcrypto/webcrypto.dart';
  ///
  /// // Public JSON Web Key data.
  /// final jwk = {
  ///   'kty': 'OKP',
  ///   'crv': 'X25519',
  ///   'x': 'coeKtJr7mBuIBzGjR_T4OFfuU3Sn85-frLUvxzg5320',
  /// };
  ///
  /// Future<void> main() async {
  ///   // Import Alice's public key
  ///   final pkA = await X25519PublicKey.importJsonWebKey(jwk);
  ///
  ///   // Export the public key as a JSON Web Key.
  ///   final exportedPublicKey = await pkA.exportJsonWebKey();
  ///
  ///   // The Map returned by `exportJsonWebKey()` can be converted to JSON with
  ///   // `jsonEncode` from `dart:convert`.
  ///   print(jsonEncode(exportedPublicKey));
  /// }
  /// ```
  /// [1]: https://www.rfc-editor.org/rfc/rfc7518.html
  Future<Map<String, dynamic>> exportJsonWebKey() => _impl.exportJsonWebKey();
}
