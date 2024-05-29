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

/// ECDH private key for deriving a shared secret.
///
/// Elliptic Curve Diffie-Hellman (ECDH) is a key agreement protocol that allows
/// two parties to establish a shared secret over an insecure channel.
/// An [EcdhPrivateKey] holds a private key that can be used to derive a
/// shared secret giving the public key from a different key pair.
/// 
/// Instances of [EcdhPrivateKey] can be imported from:
/// * PKCS8 Key using [EcdhPrivateKey.importPkcs8Key], and,
/// * JSON Web Key using [EcdhPrivateKey.importJsonWebKey].
/// 
/// A random key pair can be generated using [EcdhPrivateKey.generateKey].
/// 
/// {@template EcdhPrivateKey:example}
/// **Example**
/// ```dart
/// import 'dart:convert';
/// import 'package:webcrypto/webcrypto.dart';
/// 
/// Future<void> main() async {
///   // Alice generates a key-pair
///   final kpA = await EcdhPrivateKey.generateKey(EllipticCurve.p256);
///   
///   // Bob generates a key-pair
///   final kpB = await EcdhPrivateKey.generateKey(EllipticCurve.p256);
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
@sealed
abstract class EcdhPrivateKey {
  EcdhPrivateKey._(); // keep the constructor private.

  static Future<EcdhPrivateKey> importPkcs8Key(
    List<int> keyData,
    EllipticCurve curve,
  ) {
    return impl.ecdhPrivateKey_importPkcs8Key(keyData, curve);
  }

  static Future<EcdhPrivateKey> importJsonWebKey(
    Map<String, dynamic> jwk,
    EllipticCurve curve,
  ) {
    return impl.ecdhPrivateKey_importJsonWebKey(jwk, curve);
  }

  static Future<KeyPair<EcdhPrivateKey, EcdhPublicKey>> generateKey(
    EllipticCurve curve,
  ) {
    return impl.ecdhPrivateKey_generateKey(curve);
  }

  // Note some webcrypto implementations (chrome, not firefox) supports passing
  // null for length (in this primitive). However, you can always know the right
  // length from the curve. Note p512 can provide up to: 528 bits!!!
  //
  // See: https://tools.ietf.org/html/rfc6090#section-4
  // Notice that this is not uniformly distributed, see also:
  // https://tools.ietf.org/html/rfc6090#appendix-B
  Future<Uint8List> deriveBits(int length, EcdhPublicKey publicKey);

  Future<Uint8List> exportPkcs8Key();

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
