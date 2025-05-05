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

const _rsaPssAlgorithmName = 'RSA-PSS';

Future<RsaPssPrivateKeyImpl> rsaPssPrivateKey_importPkcs8Key(
  List<int> keyData,
  HashImpl hash,
) async {
  return _RsaPssPrivateKeyImpl(await _importKey(
    'pkcs8',
    keyData,
    subtle.Algorithm(name: _rsaPssAlgorithmName, hash: _getHashAlgorithm(hash)),
    _usagesSign,
    'private',
  ));
}

Future<RsaPssPrivateKeyImpl> rsaPssPrivateKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  HashImpl hash,
) async {
  return _RsaPssPrivateKeyImpl(await _importJsonWebKey(
    jwk,
    subtle.Algorithm(name: _rsaPssAlgorithmName, hash: _getHashAlgorithm(hash)),
    _usagesSign,
    'private',
  ));
}

Future<KeyPair<RsaPssPrivateKeyImpl, RsaPssPublicKeyImpl>>
    rsaPssPrivateKey_generateKey(
  int modulusLength,
  BigInt publicExponent,
  HashImpl hash,
) async {
  final pair = await _generateKeyPair(
    subtle.Algorithm(
      name: _rsaPssAlgorithmName,
      hash: _getHashAlgorithm(hash),
      publicExponent: _publicExponentAsBuffer(publicExponent),
      modulusLength: modulusLength,
    ),
    _usagesSignVerify,
  );
  return (
    privateKey: _RsaPssPrivateKeyImpl(pair.privateKey),
    publicKey: _RsaPssPublicKeyImpl(pair.publicKey),
  );
}

Future<RsaPssPublicKeyImpl> rsaPssPublicKey_importSpkiKey(
  List<int> keyData,
  HashImpl hash,
) async {
  return _RsaPssPublicKeyImpl(await _importKey(
    'spki',
    keyData,
    subtle.Algorithm(name: _rsaPssAlgorithmName, hash: _getHashAlgorithm(hash)),
    _usagesVerify,
    'public',
  ));
}

Future<RsaPssPublicKeyImpl> rsaPssPublicKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  HashImpl hash,
) async {
  return _RsaPssPublicKeyImpl(await _importJsonWebKey(
    jwk,
    subtle.Algorithm(name: _rsaPssAlgorithmName, hash: _getHashAlgorithm(hash)),
    _usagesVerify,
    'public',
  ));
}

final class _StaticRsaPssPrivateKeyImpl implements StaticRsaPssPrivateKeyImpl {
  const _StaticRsaPssPrivateKeyImpl();

  @override
  Future<RsaPssPrivateKeyImpl> importPkcs8Key(
    List<int> keyData,
    HashImpl hash,
  ) async {
    return await rsaPssPrivateKey_importPkcs8Key(keyData, hash);
  }

  @override
  Future<RsaPssPrivateKeyImpl> importJsonWebKey(
    Map<String, dynamic> jwk,
    HashImpl hash,
  ) async {
    return await rsaPssPrivateKey_importJsonWebKey(jwk, hash);
  }

  @override
  Future<(RsaPssPrivateKeyImpl, RsaPssPublicKeyImpl)> generateKey(
    int modulusLength,
    BigInt publicExponent,
    HashImpl hash,
  ) async {
    final KeyPair<RsaPssPrivateKeyImpl, RsaPssPublicKeyImpl> keyPair =
        await rsaPssPrivateKey_generateKey(modulusLength, publicExponent, hash);

    return (keyPair.privateKey, keyPair.publicKey);
  }
}

final class _RsaPssPrivateKeyImpl implements RsaPssPrivateKeyImpl {
  final subtle.JSCryptoKey _key;
  _RsaPssPrivateKeyImpl(this._key);

  @override
  String toString() {
    return 'Instance of \'RsaPssPrivateKey\'';
  }

  @override
  Future<Uint8List> signBytes(List<int> data, int saltLength) async {
    if (saltLength < 0) {
      throw ArgumentError.value(
        saltLength,
        'saltLength',
        'must be a positive integer',
      );
    }

    return await _sign(
      subtle.Algorithm(name: _rsaPssAlgorithmName, saltLength: saltLength),
      _key,
      data,
    );
  }

  @override
  Future<Uint8List> signStream(Stream<List<int>> data, int saltLength) async {
    return await signBytes(await _bufferStream(data), saltLength);
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

final class _StaticRsaPssPublicKeyImpl implements StaticRsaPssPublicKeyImpl {
  const _StaticRsaPssPublicKeyImpl();

  @override
  Future<RsaPssPublicKeyImpl> importSpkiKey(
    List<int> keyData,
    HashImpl hash,
  ) async {
    return await rsaPssPublicKey_importSpkiKey(keyData, hash);
  }

  @override
  Future<RsaPssPublicKeyImpl> importJsonWebKey(
    Map<String, dynamic> jwk,
    HashImpl hash,
  ) async {
    return await rsaPssPublicKey_importJsonWebKey(jwk, hash);
  }
}

final class _RsaPssPublicKeyImpl implements RsaPssPublicKeyImpl {
  final subtle.JSCryptoKey _key;
  _RsaPssPublicKeyImpl(this._key);

  @override
  String toString() {
    return 'Instance of \'RsaPssPublicKey\'';
  }

  @override
  Future<bool> verifyBytes(
    List<int> signature,
    List<int> data,
    int saltLength,
  ) async {
    if (saltLength < 0) {
      throw ArgumentError.value(
        saltLength,
        'saltLength',
        'must be a positive integer',
      );
    }

    return await _verify(
      subtle.Algorithm(name: _rsaPssAlgorithmName, saltLength: saltLength),
      _key,
      signature,
      data,
    );
  }

  @override
  Future<bool> verifyStream(
    List<int> signature,
    Stream<List<int>> data,
    int saltLength,
  ) async {
    return await verifyBytes(signature, await _bufferStream(data), saltLength);
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async {
    return await _exportJsonWebKey(_key);
  }

  @override
  Future<Uint8List> exportSpkiKey() async {
    return await _exportKey('spki', _key);
  }
}
