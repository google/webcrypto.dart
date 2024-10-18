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

part of 'impl_ffi.dart';

Future<AesCbcSecretKeyImpl> aesCbc_importRawKey(List<int> keyData) async =>
    _AesCbcSecretKeyImpl(_aesImportRawKey(keyData));

Future<AesCbcSecretKeyImpl> aesCbc_importJsonWebKey(
  Map<String, dynamic> jwk,
) async =>
    _AesCbcSecretKeyImpl(_aesImportJwkKey(
      jwk,
      expectedJwkAlgSuffix: 'CBC',
    ));

Future<AesCbcSecretKeyImpl> aesCbc_generateKey(int length) async =>
    _AesCbcSecretKeyImpl(_aesGenerateKey(length));

Stream<Uint8List> _aesCbcEncryptOrDecrypt(
  Uint8List key,
  bool encrypt,
  Stream<List<int>> source,
  List<int> iv,
) {
  return _Scope.stream((scope) async* {
    assert(key.length == 16 || key.length == 32);
    final cipher =
        key.length == 16 ? ssl.EVP_aes_128_cbc() : ssl.EVP_aes_256_cbc();
    const blockSize = AES_BLOCK_SIZE;

    final ivSize = ssl.EVP_CIPHER_iv_length(cipher);
    if (iv.length != ivSize) {
      throw ArgumentError.value(iv, 'iv', 'must be $ivSize bytes');
    }

    final ctx = scope.createEVP_CIPHER_CTX();
    _checkOpIsOne(ssl.EVP_CipherInit_ex(
      ctx,
      cipher,
      ffi.nullptr,
      scope.dataAsPointer(key),
      scope.dataAsPointer(iv),
      encrypt ? 1 : 0,
    ));

    const bufSize = 4096;

    // Allocate an input buffer
    final inBuf = scope<ffi.Uint8>(bufSize);
    final inData = inBuf.asTypedList(bufSize);

    // Allocate an output buffer, notice that BoringSSL says output cannot be
    // more than input size + blockSize - 1
    final outBuf = scope<ffi.Uint8>(bufSize + blockSize);
    final outData = outBuf.asTypedList(bufSize + blockSize);

    // Allocate and output length integer
    final outLen = scope<ffi.Int>();

    // Process data from source
    await for (final data in source) {
      var offset = 0;
      while (offset < data.length) {
        final N = math.min(data.length - offset, bufSize);
        inData.setAll(0, data.skip(offset).take(N));

        _checkOpIsOne(ssl.EVP_CipherUpdate(ctx, outBuf, outLen, inBuf, N));
        if (outLen.value > 0) {
          yield outData.sublist(0, outLen.value);
        }
        offset += N;
      }
    }
    // Output final block
    _checkOpIsOne(ssl.EVP_CipherFinal_ex(ctx, outBuf, outLen));
    if (outLen.value > 0) {
      yield outData.sublist(0, outLen.value);
    }
  });
}

final class _StaticAesCbcSecretKeyImpl implements StaticAesCbcSecretKeyImpl {
  const _StaticAesCbcSecretKeyImpl();

  @override
  Future<AesCbcSecretKeyImpl> importRawKey(List<int> keyData) async {
    // TODO: Move implementation into this method in a follow up PR
    // TODO: Move implementation into this method in a follow up PR
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
  final Uint8List _key;
  _AesCbcSecretKeyImpl(this._key);

  @override
  String toString() {
    return 'Instance of \'AesCbcSecretKey\'';
  }

  @override
  Future<Uint8List> decryptBytes(List<int> data, List<int> iv) async =>
      await _bufferStream(decryptStream(Stream.value(data), iv));

  @override
  Stream<Uint8List> decryptStream(Stream<List<int>> data, List<int> iv) =>
      _aesCbcEncryptOrDecrypt(_key, false, data, iv);

  @override
  Future<Uint8List> encryptBytes(List<int> data, List<int> iv) async =>
      await _bufferStream(encryptStream(Stream.value(data), iv));

  @override
  Stream<Uint8List> encryptStream(Stream<List<int>> data, List<int> iv) =>
      _aesCbcEncryptOrDecrypt(_key, true, data, iv);

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async =>
      _aesExportJwkKey(_key, jwkAlgSuffix: 'CBC');

  @override
  Future<Uint8List> exportRawKey() async => Uint8List.fromList(_key);
}
