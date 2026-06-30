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

part of 'impl_jni.dart';

const _aesGcmTransformation = 'AES/GCM/NoPadding';

Future<Uint8List> _aesGcmEncryptDecrypt(
  Uint8List keyData,
  List<int> data,
  List<int> iv,
  List<int>? additionalData,
  int tagLength,
  bool isEncrypt,
) async {
  final aad = additionalData ?? const <int>[];
  if (isEncrypt && data.length > (1 << 39) - 256) {
    // More than this is not allowed by Web Crypto.
    throw operationError('data may not be more than 2^39 - 256 bytes');
  }
  if (tagLength != 32 &&
      tagLength != 64 &&
      tagLength != 96 &&
      tagLength != 104 &&
      tagLength != 112 &&
      tagLength != 120 &&
      tagLength != 128) {
    throw operationError('tagLength must be 32, 64, 96, 104, 112, 120 or 128');
  }

  try {
    return jni.using((arena) {
      final algorithm = 'AES'.toJString()..releasedBy(arena);
      final transformation = _aesGcmTransformation.toJString()
        ..releasedBy(arena);
      final keyBytes = arena.copyToJByteArray(keyData);
      final secretKey = SecretKeySpec(keyBytes, algorithm)..releasedBy(arena);
      final ivBytes = arena.copyToJByteArray(_asUint8List(iv));
      final parameters = GCMParameterSpec(tagLength, ivBytes)
        ..releasedBy(arena);

      final cipher = Cipher.getInstance(transformation);
      if (cipher == null) {
        throw operationError(
          'JCA Cipher($_aesGcmTransformation) is unavailable',
        );
      }
      cipher.releasedBy(arena);

      cipher.init$2(
        isEncrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE,
        secretKey,
        parameters,
      );

      if (aad.isNotEmpty) {
        final aadBytes = arena.copyToJByteArray(_asUint8List(aad));
        cipher.updateAAD(aadBytes);
      }

      final input = arena.copyToJByteArray(_asUint8List(data));
      final output = cipher.doFinal$2(input);
      if (output == null) {
        throw operationError(
          'JCA Cipher($_aesGcmTransformation) returned null',
        );
      }
      output.releasedBy(arena);
      return output.copyToDartBytes();
    });
  } on OperationError {
    rethrow;
  } on jni.JThrowable catch (e) {
    final message = e.message;
    e.release();
    throw operationError('JCA Cipher($_aesGcmTransformation) failed: $message');
  }
}

final class _StaticAesGcmSecretKeyImpl implements StaticAesGcmSecretKeyImpl {
  const _StaticAesGcmSecretKeyImpl();

  @override
  Future<AesGcmSecretKeyImpl> importRawKey(List<int> keyData) async =>
      _AesGcmSecretKeyImpl(_aesImportRawKey(keyData));

  @override
  Future<AesGcmSecretKeyImpl> importJsonWebKey(
    Map<String, dynamic> jwk,
  ) async =>
      _AesGcmSecretKeyImpl(_aesImportJwkKey(jwk, expectedJwkAlgSuffix: 'GCM'));

  @override
  Future<AesGcmSecretKeyImpl> generateKey(int length) async =>
      _AesGcmSecretKeyImpl(_aesGenerateKey(length));
}

final class _AesGcmSecretKeyImpl implements AesGcmSecretKeyImpl {
  _AesGcmSecretKeyImpl(this._keyData);

  final Uint8List _keyData;

  @override
  Future<Uint8List> encryptBytes(
    List<int> data,
    List<int> iv, {
    List<int>? additionalData,
    int? tagLength = 128,
  }) async => _aesGcmEncryptDecrypt(
    _keyData,
    data,
    iv,
    additionalData,
    tagLength ?? 128,
    true,
  );

  @override
  Future<Uint8List> decryptBytes(
    List<int> data,
    List<int> iv, {
    List<int>? additionalData,
    int? tagLength = 128,
  }) async => _aesGcmEncryptDecrypt(
    _keyData,
    data,
    iv,
    additionalData,
    tagLength ?? 128,
    false,
  );

  @override
  Future<Uint8List> exportRawKey() async => Uint8List.fromList(_keyData);

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async =>
      _aesExportJwkKey(_keyData, jwkAlgSuffix: 'GCM');
}
