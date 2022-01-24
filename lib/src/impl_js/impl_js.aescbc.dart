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

final _aesCbcAlgorithm = subtle.Algorithm(name: 'AES-CBC');

Future<AesCbcSecretKey> aesCbc_importRawKey(List<int> keyData) async {
  return _AesCbcSecretKey(await _importKey(
    'raw',
    keyData,
    _aesCbcAlgorithm,
    _usagesEncryptDecrypt,
    'secret',
  ));
}

Future<AesCbcSecretKey> aesCbc_importJsonWebKey(
  Map<String, dynamic> jwk,
) async {
  return _AesCbcSecretKey(await _importJsonWebKey(
    jwk,
    _aesCbcAlgorithm,
    _usagesEncryptDecrypt,
    'secret',
  ));
}

Future<AesCbcSecretKey> aesCbc_generateKey(int length) async {
  return _AesCbcSecretKey(await _generateKey(
    _aesCbcAlgorithm.update(length: length),
    _usagesEncryptDecrypt,
    'secret',
  ));
}

class _AesCbcSecretKey implements AesCbcSecretKey {
  final subtle.CryptoKey _key;
  _AesCbcSecretKey(this._key);

  @override
  Future<Uint8List> decryptBytes(List<int> data, List<int> iv) async {
    ArgumentError.checkNotNull(data, 'data');
    ArgumentError.checkNotNull(iv, 'iv');
    return await _decrypt(
      _aesCbcAlgorithm.update(iv: Uint8List.fromList(iv)),
      _key,
      data,
    );
  }

  @override
  Stream<Uint8List> decryptStream(Stream<List<int>> data, List<int> iv) async* {
    yield await decryptBytes(await _bufferStream(data), iv);
  }

  @override
  Future<Uint8List> encryptBytes(List<int> data, List<int> iv) async {
    ArgumentError.checkNotNull(data, 'data');
    ArgumentError.checkNotNull(iv, 'iv');
    return await _encrypt(
      _aesCbcAlgorithm.update(iv: Uint8List.fromList(iv)),
      _key,
      data,
    );
  }

  @override
  Stream<Uint8List> encryptStream(Stream<List<int>> data, List<int> iv) async* {
    yield await encryptBytes(await _bufferStream(data), iv);
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
