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

part of impl_ffi;

Future<AesGcmSecretKey> aesGcm_importRawKey(List<int> keyData) async =>
    _AesGcmSecretKey(_aesImportRawKey(keyData));

Future<AesGcmSecretKey> aesGcm_importJsonWebKey(
  Map<String, dynamic> jwk,
) async =>
    _AesGcmSecretKey(_aesImportJwkKey(
      jwk,
      expectedJwkAlgSuffix: 'GCM',
    ));

Future<AesGcmSecretKey> aesGcm_generateKey(int length) async =>
    _AesGcmSecretKey(_aesGenerateKey(length));

Future<Uint8List> _aesGcmEncryptDecrypt(
  List<int> key,
  List<int> data,
  List<int> iv,
  List<int>? additionalData,
  int tagLength,
  bool isEncrypt,
) async {
  final additionalData_ = additionalData ??= <int>[];
  if (isEncrypt && data.length > (1 << 39) - 256) {
    // More than this is not allowed by Web crypto spec, we shall honor that.
    throw _OperationError('data may not be more than 2^39 - 256 bytes');
  }
  if (tagLength != 32 &&
      tagLength != 64 &&
      tagLength != 96 &&
      tagLength != 104 &&
      tagLength != 112 &&
      tagLength != 120 &&
      tagLength != 128) {
    throw _OperationError('tagLength must be 32, 64, 96, 104, 112, 120 or 128');
  }

  // TODO: Check iv length is less than EVP_AEAD_nonce_length
  //       More importantly, add some test cases covering this, also consider
  //       what chrome does, how firefox passes tests. And check if other
  //       primitives that accept an iv/nonce has size limitations on it.

  final scope = _Scope();
  try {
    assert(key.length == 16 || key.length == 32);
    final aead = key.length == 16
        ? ssl.EVP_aead_aes_128_gcm()
        : ssl.EVP_aead_aes_256_gcm();

    final ctx = scope.create(
      () => ssl.EVP_AEAD_CTX_new(
        aead,
        scope.dataAsPointer(key),
        key.length,
        tagLength ~/ 8,
      ),
      ssl.EVP_AEAD_CTX_free,
    );

    if (isEncrypt) {
      final outLen = scope<ffi.IntPtr>();
      final maxOut = data.length + ssl.EVP_AEAD_max_overhead(aead);
      return _withOutPointer(maxOut, (ffi.Pointer<ffi.Uint8> out) {
        _checkOpIsOne(ssl.EVP_AEAD_CTX_seal(
          ctx,
          out,
          outLen,
          maxOut,
          scope.dataAsPointer(iv),
          iv.length,
          scope.dataAsPointer(data),
          data.length,
          scope.dataAsPointer(additionalData_),
          additionalData_.length,
        ));
      }).sublist(0, outLen.value);
    } else {
      final outLen = scope<ffi.IntPtr>();
      return _withOutPointer(data.length, (ffi.Pointer<ffi.Uint8> out) {
        _checkOpIsOne(ssl.EVP_AEAD_CTX_open(
          ctx,
          out,
          outLen,
          data.length,
          scope.dataAsPointer(iv),
          iv.length,
          scope.dataAsPointer(data),
          data.length,
          scope.dataAsPointer(additionalData_),
          additionalData_.length,
        ));
      }).sublist(0, outLen.value);
    }
  } finally {
    scope.release();
  }
}

class _AesGcmSecretKey implements AesGcmSecretKey {
  final Uint8List _key;
  _AesGcmSecretKey(this._key);

  @override
  Future<Uint8List> decryptBytes(
    List<int> data,
    List<int> iv, {
    List<int>? additionalData,
    int? tagLength = 128,
  }) async =>
      _aesGcmEncryptDecrypt(
        _key,
        data,
        iv,
        additionalData,
        tagLength ?? 128,
        false,
      );

  @override
  Future<Uint8List> encryptBytes(
    List<int> data,
    List<int> iv, {
    List<int>? additionalData,
    int? tagLength = 128,
  }) async =>
      _aesGcmEncryptDecrypt(
        _key,
        data,
        iv,
        additionalData,
        tagLength ?? 128,
        true,
      );

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async =>
      _aesExportJwkKey(_key, jwkAlgSuffix: 'GCM');

  @override
  Future<Uint8List> exportRawKey() async => Uint8List.fromList(_key);
}
