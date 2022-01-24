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

final _rsassaPkcs1V15Algorithm = subtle.Algorithm(name: 'RSASSA-PKCS1-v1_5');

Future<RsassaPkcs1V15PrivateKey> rsassaPkcs1V15PrivateKey_importPkcs8Key(
  List<int> keyData,
  Hash hash,
) async {
  return _RsassaPkcs1V15PrivateKey(await _importKey(
    'pkcs8',
    keyData,
    _rsassaPkcs1V15Algorithm.update(hash: _getHashAlgorithm(hash)),
    _usagesSign,
    'private',
  ));
}

Future<RsassaPkcs1V15PrivateKey> rsassaPkcs1V15PrivateKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  Hash hash,
) async {
  return _RsassaPkcs1V15PrivateKey(await _importJsonWebKey(
    jwk,
    _rsassaPkcs1V15Algorithm.update(hash: _getHashAlgorithm(hash)),
    _usagesSign,
    'private',
  ));
}

Future<KeyPair<RsassaPkcs1V15PrivateKey, RsassaPkcs1V15PublicKey>>
    rsassaPkcs1V15PrivateKey_generateKey(
  int modulusLength,
  BigInt publicExponent,
  Hash hash,
) async {
  final pair = await _generateKeyPair(
    _rsassaPkcs1V15Algorithm.update(
      hash: _getHashAlgorithm(hash),
      publicExponent: _publicExponentAsBuffer(publicExponent),
      modulusLength: modulusLength,
    ),
    _usagesSignVerify,
  );
  return _KeyPair(
    privateKey: _RsassaPkcs1V15PrivateKey(pair.privateKey),
    publicKey: _RsassaPkcs1V15PublicKey(pair.publicKey),
  );
}

Future<RsassaPkcs1V15PublicKey> rsassaPkcs1V15PublicKey_importSpkiKey(
  List<int> keyData,
  Hash hash,
) async {
  return _RsassaPkcs1V15PublicKey(await _importKey(
    'spki',
    keyData,
    _rsassaPkcs1V15Algorithm.update(hash: _getHashAlgorithm(hash)),
    _usagesVerify,
    'public',
  ));
}

Future<RsassaPkcs1V15PublicKey> rsassaPkcs1V15PublicKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  Hash hash,
) async {
  return _RsassaPkcs1V15PublicKey(await _importJsonWebKey(
    jwk,
    _rsassaPkcs1V15Algorithm.update(hash: _getHashAlgorithm(hash)),
    _usagesVerify,
    'public',
  ));
}

class _RsassaPkcs1V15PrivateKey implements RsassaPkcs1V15PrivateKey {
  final subtle.CryptoKey _key;
  _RsassaPkcs1V15PrivateKey(this._key);

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

class _RsassaPkcs1V15PublicKey implements RsassaPkcs1V15PublicKey {
  final subtle.CryptoKey _key;
  _RsassaPkcs1V15PublicKey(this._key);

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
