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

final _aesGcmAlgorithm = subtle.Algorithm(name: 'AES-GCM');

Future<AesGcmSecretKey> aesGcm_importRawKey(List<int> keyData) async {
  return _AesGcmSecretKey(await _importKey(
    'raw',
    keyData,
    _aesGcmAlgorithm,
    _usagesEncryptDecrypt,
    'secret',
  ));
}

Future<AesGcmSecretKey> aesGcm_importJsonWebKey(
  Map<String, dynamic> jwk,
) async {
  return _AesGcmSecretKey(await _importJsonWebKey(
    jwk,
    _aesGcmAlgorithm,
    _usagesEncryptDecrypt,
    'secret',
  ));
}

Future<AesGcmSecretKey> aesGcm_generateKey(int length) async {
  return _AesGcmSecretKey(await _generateKey(
    _aesGcmAlgorithm.update(length: length),
    _usagesEncryptDecrypt,
    'secret',
  ));
}

class _AesGcmSecretKey implements AesGcmSecretKey {
  final subtle.CryptoKey _key;
  _AesGcmSecretKey(this._key);

  @override
  Future<Uint8List> decryptBytes(
    List<int> data,
    List<int> iv, {
    List<int>? additionalData,
    int? tagLength = 128,
  }) async {
    tagLength ??= 128;
    return await _decrypt(
      additionalData == null
          ? _aesGcmAlgorithm.update(
              iv: Uint8List.fromList(iv),
              tagLength: tagLength,
            )
          : _aesGcmAlgorithm.update(
              iv: Uint8List.fromList(iv),
              additionalData: Uint8List.fromList(additionalData),
              tagLength: tagLength,
            ),
      _key,
      data,
    );
  }

  @override
  Future<Uint8List> encryptBytes(
    List<int> data,
    List<int> iv, {
    List<int>? additionalData,
    int? tagLength = 128,
  }) async {
    tagLength ??= 128;
    return await _encrypt(
      additionalData == null
          ? _aesGcmAlgorithm.update(
              iv: Uint8List.fromList(iv),
              tagLength: tagLength,
            )
          : _aesGcmAlgorithm.update(
              iv: Uint8List.fromList(iv),
              additionalData: Uint8List.fromList(additionalData),
              tagLength: tagLength,
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
  Future<Uint8List> exportRawKey() async {
    return await _exportKey('raw', _key);
  }
}
