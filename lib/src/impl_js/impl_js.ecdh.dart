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

part of impl_js;

final _ecdhAlgorithmName = 'ECDH';

Future<EcdhPrivateKey> ecdhPrivateKey_importPkcs8Key(
  List<int> keyData,
  EllipticCurve curve,
) async {
  return _EcdhPrivateKey(await _importKey(
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

Future<EcdhPrivateKey> ecdhPrivateKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  EllipticCurve curve,
) async {
  if (jwk['use'] == 'enc') {
    // Chrome incorrectly forbids the 'enc' value for ECDH, hence, we strip it
    // when importing to ensure compatibility across browsers.
    // See: https://crbug.com/641499
    jwk = Map.fromEntries(jwk.entries.where((e) => e.key != 'use'));
  }
  return _EcdhPrivateKey(await _importJsonWebKey(
    jwk,
    subtle.Algorithm(
      name: _ecdhAlgorithmName,
      namedCurve: _curveToName(curve),
    ),
    _usagesDeriveBits,
    'private',
  ));
}

Future<KeyPair<EcdhPrivateKey, EcdhPublicKey>> ecdhPrivateKey_generateKey(
  EllipticCurve curve,
) async {
  final pair = await _generateKeyPair(
    subtle.Algorithm(
      name: _ecdhAlgorithmName,
      namedCurve: _curveToName(curve),
    ),
    _usagesDeriveBits,
  );
  return _KeyPair(
    privateKey: _EcdhPrivateKey(pair.privateKey),
    publicKey: _EcdhPublicKey(pair.publicKey),
  );
}

Future<EcdhPublicKey> ecdhPublicKey_importRawKey(
  List<int> keyData,
  EllipticCurve curve,
) async {
  return _EcdhPublicKey(await _importKey(
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

Future<EcdhPublicKey> ecdhPublicKey_importSpkiKey(
  List<int> keyData,
  EllipticCurve curve,
) async {
  return _EcdhPublicKey(await _importKey(
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

Future<EcdhPublicKey> ecdhPublicKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  EllipticCurve curve,
) async {
  if (jwk['use'] == 'enc') {
    // Chrome incorrectly forbids the 'enc' value for ECDH, hence, we strip it
    // when importing to ensure compatibility across browsers.
    // See: https://crbug.com/641499
    jwk = Map.fromEntries(jwk.entries.where((e) => e.key != 'use'));
  }
  return _EcdhPublicKey(await _importJsonWebKey(
    jwk,
    subtle.Algorithm(
      name: _ecdhAlgorithmName,
      namedCurve: _curveToName(curve),
    ),
    [],
    'public',
  ));
}

class _EcdhPrivateKey implements EcdhPrivateKey {
  final subtle.CryptoKey _key;
  _EcdhPrivateKey(this._key);

  @override
  Future<Uint8List> deriveBits(int length, EcdhPublicKey publicKey) async {
    ArgumentError.checkNotNull(length, 'length');
    ArgumentError.checkNotNull(publicKey, 'publicKey');
    if (publicKey is! EcdhPublicKey) {
      throw ArgumentError.value(
        publicKey,
        'publicKey',
        'custom implementations of EcdhPublicKey is not supported',
      );
    }
    final lengthInBytes = (length / 8).ceil();
    final derived = await _deriveBits(
      subtle.Algorithm(
        name: _ecdhAlgorithmName,
        public: (publicKey as _EcdhPublicKey)._key,
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

class _EcdhPublicKey implements EcdhPublicKey {
  final subtle.CryptoKey _key;
  _EcdhPublicKey(this._key);

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
