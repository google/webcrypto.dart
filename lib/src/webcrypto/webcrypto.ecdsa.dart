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

final class EcdsaPrivateKey {
  final EcdsaPrivateKeyImpl _impl;

  EcdsaPrivateKey._(this._impl); // keep the constructor private.

  factory EcdsaPrivateKey(EcdsaPrivateKeyImpl impl) {
    return EcdsaPrivateKey._(impl);
  }

  static Future<EcdsaPrivateKey> importPkcs8Key(
    List<int> keyData,
    EllipticCurve curve,
  ) async {
    final impl =
        await webCryptImpl.ecdsaPrivateKey.importPkcs8Key(keyData, curve);
    return EcdsaPrivateKey._(impl);
  }

  static Future<EcdsaPrivateKey> importJsonWebKey(
    Map<String, dynamic> jwk,
    EllipticCurve curve,
  ) async {
    final impl =
        await webCryptImpl.ecdsaPrivateKey.importJsonWebKey(jwk, curve);
    return EcdsaPrivateKey._(impl);
  }

  static Future<KeyPair<EcdsaPrivateKey, EcdsaPublicKey>> generateKey(
    EllipticCurve curve,
  ) async {
    final (privateKeyImpl, publicKeyImpl) =
        await webCryptImpl.ecdsaPrivateKey.generateKey(curve);

    final privateKey = EcdsaPrivateKey(privateKeyImpl);
    final publicKey = EcdsaPublicKey(publicKeyImpl);

    return (privateKey: privateKey, publicKey: publicKey);
  }

  /// TODO: Document that this returns the raw signature format specified
  ///       in the webcrypto specification. Which is R + S as two raw big endian
  ///       integers zero padded to fill N bytes. Where N is the number of bytes
  ///       required to encode the order of the base points of the curve.
  Future<Uint8List> signBytes(List<int> data, Hash hash) =>
      _impl.signBytes(data, hash._impl);

  Future<Uint8List> signStream(Stream<List<int>> data, Hash hash) =>
      _impl.signStream(data, hash._impl);

  Future<Uint8List> exportPkcs8Key() => _impl.exportPkcs8Key();

  Future<Map<String, dynamic>> exportJsonWebKey() => _impl.exportJsonWebKey();
}

final class EcdsaPublicKey {
  final EcdsaPublicKeyImpl _impl;

  factory EcdsaPublicKey(EcdsaPublicKeyImpl impl) {
    return EcdsaPublicKey._(impl);
  }

  EcdsaPublicKey._(this._impl); // keep the constructor private.

  /// TODO: Document this being X9.62 format
  static Future<EcdsaPublicKey> importRawKey(
    List<int> keyData,
    EllipticCurve curve,
  ) async {
    final impl = await webCryptImpl.ecdsaPublicKey.importRawKey(keyData, curve);
    return EcdsaPublicKey._(impl);
  }

  static Future<EcdsaPublicKey> importSpkiKey(
    List<int> keyData,
    EllipticCurve curve,
  ) async {
    final impl =
        await webCryptImpl.ecdsaPublicKey.importSpkiKey(keyData, curve);
    return EcdsaPublicKey._(impl);
  }

  static Future<EcdsaPublicKey> importJsonWebKey(
    Map<String, dynamic> jwk,
    EllipticCurve curve,
  ) async {
    final impl = await webCryptImpl.ecdsaPublicKey.importJsonWebKey(jwk, curve);
    return EcdsaPublicKey._(impl);
  }

  Future<bool> verifyBytes(
    List<int> signature,
    List<int> data,
    Hash hash,
  ) =>
      _impl.verifyBytes(signature, data, hash._impl);

  Future<bool> verifyStream(
    List<int> signature,
    Stream<List<int>> data,
    Hash hash,
  ) =>
      _impl.verifyStream(signature, data, hash._impl);

  /// TODO: Document this being X9.62 format
  Future<Uint8List> exportRawKey() => _impl.exportRawKey();

  Future<Uint8List> exportSpkiKey() => _impl.exportSpkiKey();

  Future<Map<String, dynamic>> exportJsonWebKey() => _impl.exportJsonWebKey();
}
