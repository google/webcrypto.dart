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

// ignore_for_file: non_constant_identifier_names

part of 'impl_js.dart';

const _ecdsaAlgorithmName = 'ECDSA';

Future<EcdsaPrivateKeyImpl> ecdsaPrivateKey_importPkcs8Key(
  List<int> keyData,
  EllipticCurve curve,
) async {
  return _EcdsaPrivateKeyImpl(await _importKey(
    'pkcs8',
    keyData,
    subtle.Algorithm(
      name: _ecdsaAlgorithmName,
      namedCurve: _curveToName(curve),
    ),
    _usagesSign,
    'private',
  ));
}

Future<EcdsaPrivateKeyImpl> ecdsaPrivateKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  EllipticCurve curve,
) async {
  return _EcdsaPrivateKeyImpl(await _importJsonWebKey(
    jwk,
    subtle.Algorithm(
      name: _ecdsaAlgorithmName,
      namedCurve: _curveToName(curve),
    ),
    _usagesSign,
    'private',
  ));
}

Future<KeyPair<EcdsaPrivateKeyImpl, EcdsaPublicKeyImpl>>
    ecdsaPrivateKey_generateKey(
  EllipticCurve curve,
) async {
  final pair = await _generateKeyPair(
    subtle.Algorithm(
      name: _ecdsaAlgorithmName,
      namedCurve: _curveToName(curve),
    ),
    _usagesSignVerify,
  );
  return (
    privateKey: _EcdsaPrivateKeyImpl(pair.privateKey),
    publicKey: _EcdsaPublicKeyImpl(pair.publicKey),
  );
}

Future<EcdsaPublicKeyImpl> ecdsaPublicKey_importRawKey(
  List<int> keyData,
  EllipticCurve curve,
) async {
  return _EcdsaPublicKeyImpl(await _importKey(
    'raw',
    keyData,
    subtle.Algorithm(
      name: _ecdsaAlgorithmName,
      namedCurve: _curveToName(curve),
    ),
    _usagesVerify,
    'public',
  ));
}

Future<EcdsaPublicKeyImpl> ecdsaPublicKey_importSpkiKey(
  List<int> keyData,
  EllipticCurve curve,
) async {
  return _EcdsaPublicKeyImpl(await _importKey(
    'spki',
    keyData,
    subtle.Algorithm(
      name: _ecdsaAlgorithmName,
      namedCurve: _curveToName(curve),
    ),
    _usagesVerify,
    'public',
  ));
}

Future<EcdsaPublicKeyImpl> ecdsaPublicKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  EllipticCurve curve,
) async {
  return _EcdsaPublicKeyImpl(await _importJsonWebKey(
    jwk,
    subtle.Algorithm(
      name: _ecdsaAlgorithmName,
      namedCurve: _curveToName(curve),
    ),
    _usagesVerify,
    'public',
  ));
}

final class _StaticEcdsaPrivateKeyImpl implements StaticEcdsaPrivateKeyImpl {
  const _StaticEcdsaPrivateKeyImpl();

  @override
  Future<EcdsaPrivateKeyImpl> importPkcs8Key(
    List<int> keyData,
    EllipticCurve curve,
  ) =>
      ecdsaPrivateKey_importPkcs8Key(keyData, curve);

  @override
  Future<EcdsaPrivateKeyImpl> importJsonWebKey(
    Map<String, dynamic> jwk,
    EllipticCurve curve,
  ) =>
      ecdsaPrivateKey_importJsonWebKey(jwk, curve);

  @override
  Future<(EcdsaPrivateKeyImpl, EcdsaPublicKeyImpl)> generateKey(
    EllipticCurve curve,
  ) async {
    final KeyPair<EcdsaPrivateKeyImpl, EcdsaPublicKeyImpl> keyPair =
        await ecdsaPrivateKey_generateKey(curve);

    return (keyPair.privateKey, keyPair.publicKey);
  }
}

final class _EcdsaPrivateKeyImpl implements EcdsaPrivateKeyImpl {
  final subtle.JSCryptoKey _key;
  _EcdsaPrivateKeyImpl(this._key);

  @override
  String toString() {
    return 'Instance of \'EcdsaPrivateKeyImpl\'';
  }

  @override
  Future<Uint8List> signBytes(List<int> data, HashImpl hash) async {
    return await _sign(
      subtle.Algorithm(
        name: _ecdsaAlgorithmName,
        hash: _getHashAlgorithm(hash),
      ),
      _key,
      data,
    );
  }

  @override
  Future<Uint8List> signStream(Stream<List<int>> data, HashImpl hash) async {
    return await signBytes(await _bufferStream(data), hash);
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async {
    return await _exportJsonWebKey(_key);
  }

  @override
  Future<Uint8List> exportPkcs8Key() async {
    return await _exportKey('pkcs8', _key);
  }
}

final class _StaticEcdsaPublicKeyImpl implements StaticEcdsaPublicKeyImpl {
  const _StaticEcdsaPublicKeyImpl();

  @override
  Future<EcdsaPublicKeyImpl> importRawKey(
    List<int> keyData,
    EllipticCurve curve,
  ) =>
      ecdsaPublicKey_importRawKey(keyData, curve);

  @override
  Future<EcdsaPublicKeyImpl> importJsonWebKey(
    Map<String, dynamic> jwk,
    EllipticCurve curve,
  ) =>
      ecdsaPublicKey_importJsonWebKey(jwk, curve);

  @override
  Future<EcdsaPublicKeyImpl> importSpkiKey(
    List<int> keyData,
    EllipticCurve curve,
  ) =>
      ecdsaPublicKey_importSpkiKey(keyData, curve);
}

final class _EcdsaPublicKeyImpl implements EcdsaPublicKeyImpl {
  final subtle.JSCryptoKey _key;
  _EcdsaPublicKeyImpl(this._key);

  @override
  String toString() {
    return 'Instance of \'EcdsaPublicKeyImpl\'';
  }

  @override
  Future<bool> verifyBytes(
      List<int> signature, List<int> data, HashImpl hash) async {
    return await _verify(
      subtle.Algorithm(
        name: _ecdsaAlgorithmName,
        hash: _getHashAlgorithm(hash),
      ),
      _key,
      signature,
      data,
    );
  }

  @override
  Future<bool> verifyStream(
    List<int> signature,
    Stream<List<int>> data,
    HashImpl hash,
  ) async {
    return await verifyBytes(signature, await _bufferStream(data), hash);
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async {
    return await _exportJsonWebKey(_key);
  }

  @override
  Future<Uint8List> exportRawKey() async {
    return await _exportKey('raw', _key);
  }

  @override
  Future<Uint8List> exportSpkiKey() async {
    return await _exportKey('spki', _key);
  }
}
