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

@sealed
abstract class EcdhPrivateKey {
  EcdhPrivateKey._(); // keep the constructor private.

  // Note. unsupported on Firefox, see EcdsaPrivateKey.importPkcs8Key
  static Future<EcdhPrivateKey> importPkcs8Key(
    List<int> keyData,
    EllipticCurve curve,
  ) {
    ArgumentError.checkNotNull(keyData, 'keyData');
    ArgumentError.checkNotNull(curve, 'curve');

    return impl.ecdhPrivateKey_importPkcs8Key(keyData, curve);
  }

  static Future<EcdhPrivateKey> importJsonWebKey(
    Map<String, dynamic> jwk,
    EllipticCurve curve,
  ) {
    ArgumentError.checkNotNull(jwk, 'jwk');
    ArgumentError.checkNotNull(curve, 'curve');

    return impl.ecdhPrivateKey_importJsonWebKey(jwk, curve);
  }

  static Future<KeyPair<EcdhPrivateKey, EcdhPublicKey>> generateKey(
    EllipticCurve curve,
  ) {
    ArgumentError.checkNotNull(curve, 'curve');

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

  // Note. unsupported on Firefox, see EcdsaPrivateKey.importPkcs8Key
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
    ArgumentError.checkNotNull(keyData, 'keyData');
    ArgumentError.checkNotNull(curve, 'curve');

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
    ArgumentError.checkNotNull(keyData, 'keyData');
    ArgumentError.checkNotNull(curve, 'curve');

    return impl.ecdhPublicKey_importSpkiKey(keyData, curve);
  }

  static Future<EcdhPublicKey> importJsonWebKey(
    Map<String, dynamic> jwk,
    EllipticCurve curve,
  ) {
    ArgumentError.checkNotNull(jwk, 'jwk');
    ArgumentError.checkNotNull(curve, 'curve');

    return impl.ecdhPublicKey_importJsonWebKey(jwk, curve);
  }

  Future<Uint8List> exportRawKey();

  /// Note: Due to bug in Chrome/BoringSSL, SPKI keys exported from Firefox < 72
  /// cannot be imported in Chrome/BoringSSL.
  /// See compatibility section in [EcdhPublicKey.importSpkiKey].
  Future<Uint8List> exportSpkiKey();

  Future<Map<String, dynamic>> exportJsonWebKey();
}
