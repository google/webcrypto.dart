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

const _rsassaPkcs1V15Algorithm = subtle.Algorithm(name: 'RSASSA-PKCS1-v1_5');

Future<RsaSsaPkcs1V15PrivateKeyImpl> rsassaPkcs1V15PrivateKey_importPkcs8Key(
  List<int> keyData,
  HashImpl hash,
) async {
  return _RsaSsaPkcs1V15PrivateKeyImpl(await _importKey(
    'pkcs8',
    keyData,
    _rsassaPkcs1V15Algorithm.update(hash: _getHashAlgorithm(hash)),
    _usagesSign,
    'private',
  ));
}

Future<RsaSsaPkcs1V15PrivateKeyImpl> rsassaPkcs1V15PrivateKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  HashImpl hash,
) async {
  return _RsaSsaPkcs1V15PrivateKeyImpl(await _importJsonWebKey(
    jwk,
    _rsassaPkcs1V15Algorithm.update(hash: _getHashAlgorithm(hash)),
    _usagesSign,
    'private',
  ));
}

Future<KeyPair<RsaSsaPkcs1V15PrivateKeyImpl, RsaSsaPkcs1V15PublicKeyImpl>>
    rsassaPkcs1V15PrivateKey_generateKey(
  int modulusLength,
  BigInt publicExponent,
  HashImpl hash,
) async {
  final pair = await _generateKeyPair(
    _rsassaPkcs1V15Algorithm.update(
      hash: _getHashAlgorithm(hash),
      publicExponent: _publicExponentAsBuffer(publicExponent),
      modulusLength: modulusLength,
    ),
    _usagesSignVerify,
  );
  return (
    privateKey: _RsaSsaPkcs1V15PrivateKeyImpl(pair.privateKey),
    publicKey: _RsaSsaPkcs1V15PublicKeyImpl(pair.publicKey),
  );
}

Future<RsaSsaPkcs1V15PublicKeyImpl> rsassaPkcs1V15PublicKey_importSpkiKey(
  List<int> keyData,
  HashImpl hash,
) async {
  return _RsaSsaPkcs1V15PublicKeyImpl(await _importKey(
    'spki',
    keyData,
    _rsassaPkcs1V15Algorithm.update(hash: _getHashAlgorithm(hash)),
    _usagesVerify,
    'public',
  ));
}

Future<RsaSsaPkcs1V15PublicKeyImpl> rsassaPkcs1V15PublicKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  HashImpl hash,
) async {
  return _RsaSsaPkcs1V15PublicKeyImpl(await _importJsonWebKey(
    jwk,
    _rsassaPkcs1V15Algorithm.update(hash: _getHashAlgorithm(hash)),
    _usagesVerify,
    'public',
  ));
}

final class _StaticRsaSsaPkcs1V15PrivateKeyImpl
    implements StaticRsaSsaPkcs1v15PrivateKeyImpl {
  const _StaticRsaSsaPkcs1V15PrivateKeyImpl();

  @override
  Future<RsaSsaPkcs1V15PrivateKeyImpl> importPkcs8Key(
      List<int> keyData, HashImpl hash) async {
    return await rsassaPkcs1V15PrivateKey_importPkcs8Key(keyData, hash);
  }

  @override
  Future<RsaSsaPkcs1V15PrivateKeyImpl> importJsonWebKey(
      Map<String, dynamic> jwk, HashImpl hash) async {
    return await rsassaPkcs1V15PrivateKey_importJsonWebKey(jwk, hash);
  }

  @override
  Future<(RsaSsaPkcs1V15PrivateKeyImpl, RsaSsaPkcs1V15PublicKeyImpl)>
      generateKey(
          int modulusLength, BigInt publicExponent, HashImpl hash) async {
    final KeyPair<RsaSsaPkcs1V15PrivateKeyImpl, RsaSsaPkcs1V15PublicKeyImpl>
        pair = await rsassaPkcs1V15PrivateKey_generateKey(
            modulusLength, publicExponent, hash);

    return (pair.privateKey, pair.publicKey);
  }
}

final class _RsaSsaPkcs1V15PrivateKeyImpl
    implements RsaSsaPkcs1V15PrivateKeyImpl {
  final subtle.JSCryptoKey _key;
  _RsaSsaPkcs1V15PrivateKeyImpl(this._key);

  @override
  Future<Uint8List> signBytes(List<int> data) async {
    return await _sign(_rsassaPkcs1V15Algorithm, _key, data);
  }

  @override
  Future<Uint8List> signStream(Stream<List<int>> data) async {
    return await signBytes(await _bufferStream(data));
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

final class _StaticRsaSsaPkcs1V15PublicKeyImpl
    implements StaticRsaSsaPkcs1v15PublicKeyImpl {
  const _StaticRsaSsaPkcs1V15PublicKeyImpl();

  @override
  Future<RsaSsaPkcs1V15PublicKeyImpl> importSpkiKey(
      List<int> keyData, HashImpl hash) async {
    return await rsassaPkcs1V15PublicKey_importSpkiKey(keyData, hash);
  }

  @override
  Future<RsaSsaPkcs1V15PublicKeyImpl> importJsonWebKey(
      Map<String, dynamic> jwk, HashImpl hash) async {
    return await rsassaPkcs1V15PublicKey_importJsonWebKey(jwk, hash);
  }
}

final class _RsaSsaPkcs1V15PublicKeyImpl
    implements RsaSsaPkcs1V15PublicKeyImpl {
  final subtle.JSCryptoKey _key;
  _RsaSsaPkcs1V15PublicKeyImpl(this._key);

  @override
  String toString() {
    return 'Instance of \'RsaSsaPkcs1V15PublicKeyImpl\'';
  }

  @override
  Future<bool> verifyBytes(List<int> signature, List<int> data) async {
    return await _verify(_rsassaPkcs1V15Algorithm, _key, signature, data);
  }

  @override
  Future<bool> verifyStream(List<int> signature, Stream<List<int>> data) async {
    return await verifyBytes(signature, await _bufferStream(data));
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
