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
abstract class EcdsaPrivateKey {
  EcdsaPrivateKey._(); // keep the constructor private.

  // TODO: document or workaround pkcs8 being unsupported on Firefox:
  //       https://bugzilla.mozilla.org/show_bug.cgi?id=1133698
  // See: https://github.com/callstats-io/pem-to-jwk/blob/master/index.js#L126
  static Future<EcdsaPrivateKey> importPkcs8Key(
    List<int> keyData,
    EllipticCurve curve,
  ) {
    ArgumentError.checkNotNull(keyData, 'keyData');
    ArgumentError.checkNotNull(curve, 'curve');

    return impl.ecdsaPrivateKey_importPkcs8Key(keyData, curve);
  }

  static Future<EcdsaPrivateKey> importJsonWebKey(
    Map<String, dynamic> jwk,
    EllipticCurve curve,
  ) {
    ArgumentError.checkNotNull(jwk, 'jwk');
    ArgumentError.checkNotNull(curve, 'curve');

    return impl.ecdsaPrivateKey_importJsonWebKey(jwk, curve);
  }

  static Future<KeyPair<EcdsaPrivateKey, EcdsaPublicKey>> generateKey(
    EllipticCurve curve,
  ) {
    ArgumentError.checkNotNull(curve, 'curve');

    return impl.ecdsaPrivateKey_generateKey(curve);
  }

  /// TODO: Document that this returns the raw signature format specified
  ///       in the webcrypto specification. Which is R + S as two raw big endian
  ///       integers zero padded to fill N bytes. Where N is the number of bytes
  ///       required to encode the order of the base points of the curve.
  Future<Uint8List> signBytes(List<int> data, Hash hash);
  Future<Uint8List> signStream(Stream<List<int>> data, Hash hash);

  // Note. unsupported on Firefox, see EcdsaPrivateKey.importPkcs8Key
  Future<Uint8List> exportPkcs8Key();

  Future<Map<String, dynamic>> exportJsonWebKey();
}

@sealed
abstract class EcdsaPublicKey {
  EcdsaPublicKey._(); // keep the constructor private.

  /// TODO: Document this being X9.62 format
  static Future<EcdsaPublicKey> importRawKey(
    List<int> keyData,
    EllipticCurve curve,
  ) {
    ArgumentError.checkNotNull(keyData, 'keyData');
    ArgumentError.checkNotNull(curve, 'curve');

    return impl.ecdsaPublicKey_importRawKey(keyData, curve);
  }

  static Future<EcdsaPublicKey> importSpkiKey(
    List<int> keyData,
    EllipticCurve curve,
  ) {
    ArgumentError.checkNotNull(keyData, 'keyData');
    ArgumentError.checkNotNull(curve, 'curve');

    return impl.ecdsaPublicKey_importSpkiKey(keyData, curve);
  }

  static Future<EcdsaPublicKey> importJsonWebKey(
    Map<String, dynamic> jwk,
    EllipticCurve curve,
  ) {
    ArgumentError.checkNotNull(jwk, 'jwk');
    ArgumentError.checkNotNull(curve, 'curve');

    return impl.ecdsaPublicKey_importJsonWebKey(jwk, curve);
  }

  Future<bool> verifyBytes(
    List<int> signature,
    List<int> data,
    Hash hash,
  );

  Future<bool> verifyStream(
    List<int> signature,
    Stream<List<int>> data,
    Hash hash,
  );

  /// TODO: Document this being X9.62 format
  Future<Uint8List> exportRawKey();

  Future<Uint8List> exportSpkiKey();

  Future<Map<String, dynamic>> exportJsonWebKey();
}
