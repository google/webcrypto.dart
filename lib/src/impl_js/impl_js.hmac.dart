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

final _hmacAlgorithm = subtle.Algorithm(name: 'HMAC');

Future<HmacSecretKey> hmacSecretKey_importRawKey(
  List<int> keyData,
  Hash hash, {
  int? length,
}) async {
  return _HmacSecretKey(await _importKey(
    'raw',
    keyData,
    length == null
        ? subtle.Algorithm(
            name: 'HMAC',
            hash: _getHashAlgorithm(hash),
          )
        : subtle.Algorithm(
            name: 'HMAC',
            hash: _getHashAlgorithm(hash),
            length: length,
          ),
    _usagesSignVerify,
    'secret',
  ));
}

Future<HmacSecretKey> hmacSecretKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  Hash hash, {
  int? length,
}) async {
  return _HmacSecretKey(await _importJsonWebKey(
    jwk,
    length == null
        ? subtle.Algorithm(
            name: 'HMAC',
            hash: _getHashAlgorithm(hash),
          )
        : subtle.Algorithm(
            name: 'HMAC',
            hash: _getHashAlgorithm(hash),
            length: length,
          ),
    _usagesSignVerify,
    'secret',
  ));
}

Future<HmacSecretKey> hmacSecretKey_generateKey(Hash hash,
    {int? length}) async {
  return _HmacSecretKey(await _generateKey(
    length == null
        ? subtle.Algorithm(
            name: 'HMAC',
            hash: _getHashAlgorithm(hash),
          )
        : subtle.Algorithm(
            name: 'HMAC',
            hash: _getHashAlgorithm(hash),
            length: length,
          ),
    _usagesSignVerify,
    'secret',
  ));
}

class _HmacSecretKey implements HmacSecretKey {
  final subtle.CryptoKey _key;
  _HmacSecretKey(this._key);

  @override
  Future<Uint8List> signBytes(List<int> data) async {
    return await _sign(_hmacAlgorithm, _key, data);
  }

  @override
  Future<Uint8List> signStream(Stream<List<int>> data) async {
    return await signBytes(await _bufferStream(data));
  }

  @override
  Future<bool> verifyBytes(List<int> signature, List<int> data) async {
    return await _verify(_hmacAlgorithm, _key, signature, data);
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
  Future<Uint8List> exportRawKey() async {
    return await _exportKey('raw', _key);
  }
}
