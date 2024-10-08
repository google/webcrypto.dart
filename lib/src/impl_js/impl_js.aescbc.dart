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

const _aesCbcAlgorithm = subtle.Algorithm(name: 'AES-CBC');

Future<AesCbcSecretKeyImpl> aesCbc_importRawKey(List<int> keyData) async {
  return _AesCbcSecretKeyImpl(await _importKey(
    'raw',
    keyData,
    _aesCbcAlgorithm,
    _usagesEncryptDecrypt,
    'secret',
  ));
}

Future<AesCbcSecretKeyImpl> aesCbc_importJsonWebKey(
  Map<String, dynamic> jwk,
) async {
  return _AesCbcSecretKeyImpl(await _importJsonWebKey(
    jwk,
    _aesCbcAlgorithm,
    _usagesEncryptDecrypt,
    'secret',
  ));
}

Future<AesCbcSecretKeyImpl> aesCbc_generateKey(int length) async {
  return _AesCbcSecretKeyImpl(await _generateKey(
    _aesCbcAlgorithm.update(length: length),
    _usagesEncryptDecrypt,
    'secret',
  ));
}

final class _StaticAesCbcSecretKeyImpl implements StaticAesCbcSecretKeyImpl {
  const _StaticAesCbcSecretKeyImpl();

  @override
  Future<AesCbcSecretKeyImpl> importRawKey(List<int> keyData) async {
    return await aesCbc_importRawKey(keyData);
  }

  @override
  Future<AesCbcSecretKeyImpl> importJsonWebKey(Map<String, dynamic> jwk) async {
    return await aesCbc_importJsonWebKey(jwk);
  }

  @override
  Future<AesCbcSecretKeyImpl> generateKey(int length) async {
    return await aesCbc_generateKey(length);
  }
}

final class _AesCbcSecretKeyImpl implements AesCbcSecretKeyImpl {
  final subtle.JSCryptoKey _key;
  _AesCbcSecretKeyImpl(this._key);

  @override
  String toString() {
    return 'Instance of \'AesCbcSecretKey\'';
  }

  @override
  Future<Uint8List> decryptBytes(List<int> data, List<int> iv) async {
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
