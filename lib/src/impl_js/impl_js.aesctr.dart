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

const _aesCtrAlgorithm = subtle.Algorithm(name: 'AES-CTR');

Future<AesCtrSecretKeyImpl> aesCtr_importRawKey(List<int> keyData) async {
  return _AesCtrSecretKeyImpl(
    await _importKey(
      'raw',
      keyData,
      _aesCtrAlgorithm,
      _usagesEncryptDecrypt,
      'secret',
    ),
  );
}

Future<AesCtrSecretKeyImpl> aesCtr_importJsonWebKey(
  Map<String, dynamic> jwk,
) async {
  return _AesCtrSecretKeyImpl(
    await _importJsonWebKey(
      jwk,
      _aesCtrAlgorithm,
      _usagesEncryptDecrypt,
      'secret',
    ),
  );
}

Future<AesCtrSecretKeyImpl> aesCtr_generateKey(int length) async {
  return _AesCtrSecretKeyImpl(
    await _generateKey(
      _aesCtrAlgorithm.update(length: length),
      _usagesEncryptDecrypt,
      'secret',
    ),
  );
}

final class _StaticAesCtrSecretKeyImpl implements StaticAesCtrSecretKeyImpl {
  const _StaticAesCtrSecretKeyImpl();

  @override
  Future<AesCtrSecretKeyImpl> importRawKey(List<int> keyData) async {
    return await aesCtr_importRawKey(keyData);
  }

  @override
  Future<AesCtrSecretKeyImpl> importJsonWebKey(Map<String, dynamic> jwk) async {
    return await aesCtr_importJsonWebKey(jwk);
  }

  @override
  Future<AesCtrSecretKeyImpl> generateKey(int length) async {
    return await aesCtr_generateKey(length);
  }
}

final class _AesCtrSecretKeyImpl implements AesCtrSecretKeyImpl {
  final subtle.JSCryptoKey _key;
  _AesCtrSecretKeyImpl(this._key);

  @override
  String toString() {
    return 'Instance of \'AesCtrSecretKey\'';
  }

  @override
  Future<Uint8List> decryptBytes(
    List<int> data,
    List<int> counter,
    int length,
  ) async {
    return await _decrypt(
      _aesCtrAlgorithm.update(
        counter: Uint8List.fromList(counter),
        length: length,
      ),
      _key,
      data,
    );
  }

  @override
  Stream<Uint8List> decryptStream(
    Stream<List<int>> data,
    List<int> counter,
    int length,
  ) async* {
    yield await decryptBytes(await _bufferStream(data), counter, length);
  }

  @override
  Future<Uint8List> encryptBytes(
    List<int> data,
    List<int> counter,
    int length,
  ) async {
    return await _encrypt(
      _aesCtrAlgorithm.update(
        counter: Uint8List.fromList(counter),
        length: length,
      ),
      _key,
      data,
    );
  }

  @override
  Stream<Uint8List> encryptStream(
    Stream<List<int>> data,
    List<int> counter,
    int length,
  ) async* {
    yield await encryptBytes(await _bufferStream(data), counter, length);
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
