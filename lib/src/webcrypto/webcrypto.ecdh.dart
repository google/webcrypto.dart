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

/// Elliptic Curve Diffie-Hellman (ECDH) is a key agreement protocol that allows
/// two parties to establish a shared secret over an insecure channel.
/// 
/// An [EcdhPrivateKey] instance represents a private key that can be used to
/// derive a shared secret with a public key.
/// 
/// Instances of [EcdhPrivateKey] can be imported from:
/// * PKCS8 Key using [EcdhPrivateKey.importPkcs8Key], and,
/// * JSON Web Key using [EcdhPrivateKey.importJsonWebKey].
/// 
/// A random key pair can be generated using [EcdhPrivateKey.generateKey].
/// 
/// **Example**
/// ```dart
/// import 'package:webcrypto/webcrypto.dart';
/// 
/// Future<void> main() async {
///   // Generate a new key pair using the P-256 curve.
///   final keyPair = await EcdhPrivateKey.generateKey(EllipticCurve.p256);
///   
///   // Derive 256 bits from the private key using the public key.
///   final derivedBits = await keyPair.privateKey.deriveBits(256, keyPair.publicKey);
/// 
///   // Export the private key as a JSON Web Key.
///   final exportedPrivateKey = await keyPair.privateKey.exportJsonWebKey();
/// }
/// ```
@sealed
abstract class EcdhPrivateKey {
  EcdhPrivateKey._(); // keep the constructor private.

  /// Import [EcdhPrivateKey] using the PKCS8 format[1].
  /// The [keyData] parameter is an octet string whose 
  /// contents are the value of the private key.
  /// The [curve] parameter specifies the curve to use 
  /// for the key pair.
  /// 
  /// **Example**
  /// ```dart
  /// import 'package:webcrypto/webcrypto.dart';
  /// 
  /// final pkcs8Key = [ /* ... */ ];
  /// 
  /// Future<void> main() async {
  ///   // Import the private key from PKCS8 format.
  ///   final privateKey = await EcdhPrivateKey.importPkcs8Key(
  ///     pkcs8Key,
  ///     EllipticCurve.p256,
  ///   );
  /// }
  /// ```
  /// 
  /// [1]: https://datatracker.ietf.org/doc/html/rfc5208
  static Future<EcdhPrivateKey> importPkcs8Key(
    List<int> keyData,
    EllipticCurve curve,
  ) {
  // Note. unsupported on Firefox, see EcdsaPrivateKey.importPkcs8Key
    return impl.ecdhPrivateKey_importPkcs8Key(keyData, curve);
  }

  /// Import [EcdhPrivateKey] from a [JSON Web Key][1].
  /// 
  /// JSON Web Keys imported using [EcdhPrivateKey.importJsonWebKey] must 
  /// have `"kty": "EC"` and MUST have the following parameters:
  /// * `"crv"`: The curve used with the key. This MUST match the curve
  ///  parameter.
  /// * `"x"`: The x coordinate for the Elliptic Curve point represented
  /// as a base64url encoded string. The length of this octet string MUST
  /// be the full size of a coordinate for the curve specified in the `"crv"`
  /// parameter.
  /// * `"y"`: The y coordinate for the Elliptic Curve point represented
  /// as a base64url encoded string. The length of this octet string MUST
  /// be the full size of a coordinate for the curve specified in the `"crv"`
  /// parameter.
  /// * `"d"`: The private key for the Elliptic Curve point represented as a
  /// base64url encoded string. The length of this octet string MUST be
  /// 32 bytes for `"crv": "P-256"`, 48 bytes for `"crv": "P-384"`, and
  /// 66 bytes for `"crv": "P-521"`.
  /// 
  /// For importing a JWK with:
  /// * `"crv": "P-256"`, use [EllipticCurve.p256]
  /// * `"crv": "P-384"`, use [EllipticCurve.p384]
  /// * `"crv": "P-521"`, use [EllipticCurve.p521]
  /// 
  /// **Example**
  /// ```dart
  /// import 'package:webcrypto/webcrypto.dart';
  /// 
  /// // JSON Web Key as a string containing JSON.
  /// final jwk = {
  ///   'kty': 'EC',
  ///   'crv': 'P-256',
  ///   'x': 'kgR_PqO07L8sZOBbw6rvv7O_f7clqDeiE3WnMkb5EoI',
  ///   'y': 'djI-XqCqSyO9GFk_QT_stROMCAROIvU8KOORBgQUemE',
  ///   'd': '5aPFSt0UFVXYGu-ZKyC9FQIUOAMmnjzdIwkxCMe3Iok',
  /// };
  /// 
  /// Future<void> main() async {
  ///   // Import secret key from decoded JSON.
  ///   final jsonWebKey = await EcdhPrivateKey.importJsonWebKey(
  ///     jwk,
  ///     EllipticCurve.p256,
  ///   );
  /// 
  ///   // Export the key (print it in same format as it was given).
  ///   final exportedJsonWebKey = await jsonWebKey.exportJsonWebKey();
  ///   print(exportedJsonWebKey);
  /// }
  /// ```
  /// 
  /// [1]: https://www.rfc-editor.org/rfc/rfc7518.html#section-6.2
  static Future<EcdhPrivateKey> importJsonWebKey(
    Map<String, dynamic> jwk,
    EllipticCurve curve,
  ) {
    return impl.ecdhPrivateKey_importJsonWebKey(jwk, curve);
  }

  /// Generate a new [EcdhPrivateKey] and [EcdhPublicKey] pair.
  /// The [curve] parameter specifies the curve to use for the key pair.
  /// 
  /// To generate a key pair using the P-256 curve, use [EllipticCurve.p256].
  /// To generate a key pair using the P-384 curve, use [EllipticCurve.p384].
  /// To generate a key pair using the P-521 curve, use [EllipticCurve.p521].
  /// 
  /// **Example**
  /// ```dart
  /// import 'package:webcrypto/webcrypto.dart';
  /// 
  /// Future<void> main() async {
  ///   // Generate a new key pair using the P-256 curve.
  ///   final keyPair = await EcdhPrivateKey.generateKey(EllipticCurve.p256);
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
  static Future<KeyPair<EcdhPrivateKey, EcdhPublicKey>> generateKey(
    EllipticCurve curve,
  ) {
    return impl.ecdhPrivateKey_generateKey(curve);
  }

  /// Derive an array of bits from the [EcdhPrivateKey].
  /// The [length] parameter specifies the number of bits to derive and 
  /// should be multiples of 8.
  /// The [publicKey] parameter is the [EcdhPublicKey].
  /// 
  /// **Example**
  /// ```dart
  /// import 'package:webcrypto/webcrypto.dart';
  /// 
  /// Future<void> main() async {
  ///   // Generate a new key pair using the P-256 curve.
  ///   final keyPair = await EcdhPrivateKey.generateKey(EllipticCurve.p256);
  /// 
  ///   // Derive 256 bits from the private key using the public key.
  ///   final derivedBits = await keyPair.privateKey.deriveBits(256, keyPair.publicKey);
  ///   print(derivedBits);
  /// }
  /// ```
  Future<Uint8List> deriveBits(int length, EcdhPublicKey publicKey);
  // Note some webcrypto implementations (chrome, not firefox) supports passing
  // null for length (in this primitive). However, you can always know the right
  // length from the curve. Note p512 can provide up to: 528 bits!!!
  //
  // See: https://tools.ietf.org/html/rfc6090#section-4
  // Notice that this is not uniformly distributed, see also:
  // https://tools.ietf.org/html/rfc6090#appendix-B

  /// Export the [EcdhPrivateKey] as a PKCS8 key.
  /// This returns the private key as an octet string.
  /// 
  /// **Example**
  /// ```dart
  /// import 'package:webcrypto/webcrypto.dart';
  /// 
  /// Future<void> main() async {
  ///   // Generate a new key pair using the P-256 curve.
  ///   final keyPair = await EcdhPrivateKey.generateKey(EllipticCurve.p256);
  /// 
  ///   // Export the private key (print it in same format as it was given).
  ///   final exportedPkcs8Key = await privateKey.exportPkcs8Key();
  ///   print(exportedPkcs8Key);
  /// }
  /// ```
  /// 
  Future<Uint8List> exportPkcs8Key();
  // Note. unsupported on Firefox, see EcdsaPrivateKey.importPkcs8Key

  /// Export the [EcdhPrivateKey] and [EcPublicKey] as a [JSON Web Key][1].
  /// 
  /// **Example**
  /// ```dart
  /// import 'package:webcrypto/webcrypto.dart';
  /// 
  /// Future<void> main() async {
  ///   // Generate a new key pair using the P-256 curve.
  ///   final keyPair = await EcdhPrivateKey.generateKey(EllipticCurve.p256);
  ///   
  ///   // Export the private key as a JSON Web Key.
  ///   final exportedPrivateKey = await keyPair.privateKey.exportJsonWebKey();
  ///   print(exportedPrivateKey);
  /// 
  ///   // Export the public key as a JSON Web Key.
  ///   final exportedPublicKey = await keyPair.publicKey.exportJsonWebKey();
  ///   print(exportedPublicKey);
  /// }
  /// ```
  /// [1]: https://www.rfc-editor.org/rfc/rfc7518.html#section-6.2
  Future<Map<String, dynamic>> exportJsonWebKey();
}

@sealed
abstract class EcdhPublicKey {
  EcdhPublicKey._(); // keep the constructor private.

  /// TODO: find out of this works on Firefox
  static Future<EcdhPublicKey> importRawKey(
    List<int> keyData,
    EllipticCurve curve,
  ) {
    return impl.ecdhPublicKey_importRawKey(keyData, curve);
  }

  /// ## Compatibility
  /// TODO: explain that Chrome can't import SPKI keys from Firefox < 72.
  ///       This is a bug in Chrome / BoringSSL (and package:webcrypto)
  ///
  /// Chrome / BoringSSL doesn't recognize `id-ecDH`, but only `id-ecPublicKey`,
  /// See: https://crbug.com/389400
  ///
  /// Chrome / BoringSSL exports `id-ecDH`, but Firefox exports
  /// `id-ecPublicKey`. Note that Firefox < 72 can import both SPKI keys
  /// exported by both Chrome, BoringSSL and Firefox. While Chrome and BoringSSL
  /// cannot import SPKI keys from Firefox < 72.
  ///
  /// Firefox 72 and later exports SPKI keys with OID `id-ecPublicKey`, thus,
  /// this is not a problem.
  static Future<EcdhPublicKey> importSpkiKey(
    List<int> keyData,
    EllipticCurve curve,
  ) {
    return impl.ecdhPublicKey_importSpkiKey(keyData, curve);
  }

  static Future<EcdhPublicKey> importJsonWebKey(
    Map<String, dynamic> jwk,
    EllipticCurve curve,
  ) {
    return impl.ecdhPublicKey_importJsonWebKey(jwk, curve);
  }

  Future<Uint8List> exportRawKey();

  /// Note: Due to bug in Chrome/BoringSSL, SPKI keys exported from Firefox < 72
  /// cannot be imported in Chrome/BoringSSL.
  /// See compatibility section in [EcdhPublicKey.importSpkiKey].
  Future<Uint8List> exportSpkiKey();

  Future<Map<String, dynamic>> exportJsonWebKey();
}
