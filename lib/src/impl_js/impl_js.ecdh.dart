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

const _ecdhAlgorithmName = 'ECDH';

Future<EcdhPrivateKeyImpl> ecdhPrivateKey_importPkcs8Key(
  List<int> keyData,
  EllipticCurve curve,
) async {
  return _EcdhPrivateKeyImpl(await _importKey(
    'pkcs8',
    keyData,
    subtle.Algorithm(
      name: _ecdhAlgorithmName,
      namedCurve: _curveToName(curve),
    ),
    _usagesDeriveBits,
    'private',
  ));
}

Future<EcdhPrivateKeyImpl> ecdhPrivateKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  EllipticCurve curve,
) async {
  if (jwk['use'] == 'enc') {
    // Chrome incorrectly forbids the 'enc' value for ECDH, hence, we strip it
    // when importing to ensure compatibility across browsers.
    // See: https://crbug.com/641499
    jwk = Map.fromEntries(jwk.entries.where((e) => e.key != 'use'));
  }
  return _EcdhPrivateKeyImpl(await _importJsonWebKey(
    jwk,
    subtle.Algorithm(
      name: _ecdhAlgorithmName,
      namedCurve: _curveToName(curve),
    ),
    _usagesDeriveBits,
    'private',
  ));
}

Future<KeyPair<EcdhPrivateKeyImpl, EcdhPublicKeyImpl>>
    ecdhPrivateKey_generateKey(
  EllipticCurve curve,
) async {
  final pair = await _generateKeyPair(
    subtle.Algorithm(
      name: _ecdhAlgorithmName,
      namedCurve: _curveToName(curve),
    ),
    _usagesDeriveBits,
  );
  return (
    privateKey: _EcdhPrivateKeyImpl(pair.privateKey),
    publicKey: _EcdhPublicKeyImpl(pair.publicKey),
  );
}

Future<EcdhPublicKeyImpl> ecdhPublicKey_importRawKey(
  List<int> keyData,
  EllipticCurve curve,
) async {
  return _EcdhPublicKeyImpl(await _importKey(
    'raw',
    keyData,
    subtle.Algorithm(
      name: _ecdhAlgorithmName,
      namedCurve: _curveToName(curve),
    ),
    [],
    'public',
  ));
}

Future<EcdhPublicKeyImpl> ecdhPublicKey_importSpkiKey(
  List<int> keyData,
  EllipticCurve curve,
) async {
  return _EcdhPublicKeyImpl(await _importKey(
    'spki',
    keyData,
    subtle.Algorithm(
      name: _ecdhAlgorithmName,
      namedCurve: _curveToName(curve),
    ),
    [],
    'public',
  ));
}

Future<EcdhPublicKeyImpl> ecdhPublicKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  EllipticCurve curve,
) async {
  if (jwk['use'] == 'enc') {
    // Chrome incorrectly forbids the 'enc' value for ECDH, hence, we strip it
    // when importing to ensure compatibility across browsers.
    // See: https://crbug.com/641499
    jwk = Map.fromEntries(jwk.entries.where((e) => e.key != 'use'));
  }
  return _EcdhPublicKeyImpl(await _importJsonWebKey(
    jwk,
    subtle.Algorithm(
      name: _ecdhAlgorithmName,
      namedCurve: _curveToName(curve),
    ),
    [],
    'public',
  ));
}

final class _StaticEcdhPrivateKeyImpl implements StaticEcdhPrivateKeyImpl {
  const _StaticEcdhPrivateKeyImpl();

  @override
  Future<EcdhPrivateKeyImpl> importPkcs8Key(
          List<int> keyData, EllipticCurve curve) =>
      ecdhPrivateKey_importPkcs8Key(keyData, curve);

  @override
  Future<EcdhPrivateKeyImpl> importJsonWebKey(
          Map<String, dynamic> jwk, EllipticCurve curve) =>
      ecdhPrivateKey_importJsonWebKey(jwk, curve);

  @override
  Future<(EcdhPrivateKeyImpl, EcdhPublicKeyImpl)> generateKey(
      EllipticCurve curve) async {
    final KeyPair<EcdhPrivateKeyImpl, EcdhPublicKeyImpl> keyPair =
        await ecdhPrivateKey_generateKey(curve);

    return (keyPair.privateKey, keyPair.publicKey);
  }
}

final class _EcdhPrivateKeyImpl implements EcdhPrivateKeyImpl {
  final subtle.JSCryptoKey _key;
  _EcdhPrivateKeyImpl(this._key);

  @override
  String toString() {
    return 'Instance of \'EcdhPrivateKeyImpl\'';
  }

  @override
  Future<Uint8List> deriveBits(int length, EcdhPublicKeyImpl publicKey) async {
    if (publicKey is! _EcdhPublicKeyImpl) {
      throw ArgumentError.value(
        publicKey,
        'publicKey',
        'custom implementations of EcdhPublicKeyImpl is not supported',
      );
    }
    final lengthInBytes = (length / 8).ceil();
    final derived = await _deriveBits(
      subtle.Algorithm(
        name: _ecdhAlgorithmName,
        public: publicKey._key,
      ),
      _key,
      // Always deriveBits in multiples of 8 as required by Firefox, see:
      // https://hg.mozilla.org/mozilla-central/file/1c9b97bed37830e39642bfa7e73dbc2ea860662a/dom/crypto/WebCryptoTask.cpp#l2667
      // Chrome does handle a length that is not a multiple of 8, however, cost
      // of normalizing across browsers behavior seems negligible.
      lengthInBytes * 8,
      invalidAccessErrorIsArgumentError: true,
    );
    // Only return the first [length] bits from derived.
    final zeroBits = lengthInBytes * 8 - length;
    assert(zeroBits < 8);
    if (zeroBits > 0) {
      derived.last &= ((0xff << zeroBits) & 0xff);
    }
    return derived;
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

final class _StaticEcdhPublicKeyImpl implements StaticEcdhPublicKeyImpl {
  const _StaticEcdhPublicKeyImpl();

  @override
  Future<EcdhPublicKeyImpl> importRawKey(
          List<int> keyData, EllipticCurve curve) =>
      ecdhPublicKey_importRawKey(keyData, curve);

  @override
  Future<EcdhPublicKeyImpl> importSpkiKey(
          List<int> keyData, EllipticCurve curve) =>
      ecdhPublicKey_importSpkiKey(keyData, curve);

  @override
  Future<EcdhPublicKeyImpl> importJsonWebKey(
          Map<String, dynamic> jwk, EllipticCurve curve) =>
      ecdhPublicKey_importJsonWebKey(jwk, curve);
}

final class _EcdhPublicKeyImpl implements EcdhPublicKeyImpl {
  final subtle.JSCryptoKey _key;
  _EcdhPublicKeyImpl(this._key);

  @override
  String toString() {
    return 'Instance of \'EcdhPublicKeyImpl\'';
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
