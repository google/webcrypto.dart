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

final _rsaOaepAlgorithmName = 'RSA-OAEP';

Future<RsaOaepPrivateKey> rsaOaepPrivateKey_importPkcs8Key(
  List<int> keyData,
  Hash hash,
) async {
  return _RsaOaepPrivateKey(await _importKey(
    'pkcs8',
    keyData,
    subtle.Algorithm(
      name: _rsaOaepAlgorithmName,
      hash: _getHashAlgorithm(hash),
    ),
    _usagesDecrypt,
    'private',
  ));
}

Future<RsaOaepPrivateKey> rsaOaepPrivateKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  Hash hash,
) async {
  return _RsaOaepPrivateKey(await _importJsonWebKey(
    jwk,
    subtle.Algorithm(
      name: _rsaOaepAlgorithmName,
      hash: _getHashAlgorithm(hash),
    ),
    _usagesDecrypt,
    'private',
  ));
}

Future<KeyPair<RsaOaepPrivateKey, RsaOaepPublicKey>>
    rsaOaepPrivateKey_generateKey(
  int modulusLength,
  BigInt publicExponent,
  Hash hash,
) async {
  final pair = await _generateKeyPair(
    subtle.Algorithm(
      name: _rsaOaepAlgorithmName,
      hash: _getHashAlgorithm(hash),
      publicExponent: _publicExponentAsBuffer(publicExponent),
      modulusLength: modulusLength,
    ),
    _usagesEncryptDecrypt,
  );
  return _KeyPair(
    privateKey: _RsaOaepPrivateKey(pair.privateKey),
    publicKey: _RsaOaepPublicKey(pair.publicKey),
  );
}

Future<RsaOaepPublicKey> rsaOaepPublicKey_importSpkiKey(
  List<int> keyData,
  Hash hash,
) async {
  return _RsaOaepPublicKey(await _importKey(
    'spki',
    keyData,
    subtle.Algorithm(
      name: _rsaOaepAlgorithmName,
      hash: _getHashAlgorithm(hash),
    ),
    _usagesEncrypt,
    'public',
  ));
}

Future<RsaOaepPublicKey> rsaOaepPublicKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  Hash hash,
) async {
  return _RsaOaepPublicKey(await _importJsonWebKey(
    jwk,
    subtle.Algorithm(
      name: _rsaOaepAlgorithmName,
      hash: _getHashAlgorithm(hash),
    ),
    _usagesEncrypt,
    'public',
  ));
}

class _RsaOaepPrivateKey implements RsaOaepPrivateKey {
  final subtle.CryptoKey _key;
  _RsaOaepPrivateKey(this._key);

  @override
  Future<Uint8List> decryptBytes(List<int> data, {List<int>? label}) async {
    return _decrypt(
      label == null
          ? subtle.Algorithm(name: _rsaOaepAlgorithmName)
          : subtle.Algorithm(
              name: _rsaOaepAlgorithmName,
              label: Uint8List.fromList(label),
            ),
      _key,
      data,
    );
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

class _RsaOaepPublicKey implements RsaOaepPublicKey {
  final subtle.CryptoKey _key;
  _RsaOaepPublicKey(this._key);

  @override
  Future<Uint8List> encryptBytes(List<int> data, {List<int>? label}) async {
    return _encrypt(
      label == null
          ? subtle.Algorithm(name: _rsaOaepAlgorithmName)
          : subtle.Algorithm(
              name: _rsaOaepAlgorithmName,
              label: Uint8List.fromList(label),
            ),
      _key,
      data,
    );
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
