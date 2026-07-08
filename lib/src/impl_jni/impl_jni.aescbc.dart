// Copyright 2026 Google LLC
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

const _aesCbcTransformation = 'AES/CBC/PKCS5Padding';

Cipher _createAesCbcCipher(Uint8List keyData, Uint8List iv, bool isEncrypt) {
  if (iv.length != 16) {
    throw ArgumentError.value(iv, 'iv', 'must be 16 bytes');
  }

  return jni.using((arena) {
    final algorithm = 'AES'.toJString()..releasedBy(arena);
    final transformation = _aesCbcTransformation.toJString()..releasedBy(arena);
    final keyBytes = arena.copyToJByteArray(keyData);
    final secretKey = SecretKeySpec(keyBytes, algorithm)..releasedBy(arena);
    final ivBytes = arena.copyToJByteArray(iv);
    final parameters = IvParameterSpec(ivBytes)..releasedBy(arena);

    final cipher = Cipher.getInstance(transformation);
    if (cipher == null) {
      throw operationError('JCA Cipher($_aesCbcTransformation) is unavailable');
    }

    var initialized = false;
    try {
      cipher.init$2(
        isEncrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE,
        secretKey,
        parameters,
      );
      initialized = true;
    } finally {
      if (!initialized) {
        cipher.release();
      }
    }

    return cipher;
  });
}

Future<Uint8List> _aesCbcEncryptDecryptBytes(
  Uint8List keyData,
  List<int> data,
  List<int> iv,
  bool isEncrypt,
) async {
  Cipher? cipher;
  try {
    cipher = _createAesCbcCipher(keyData, _asUint8List(iv), isEncrypt);
    return jni.using((arena) {
      final bytes = _asUint8List(data);
      final input = arena.copyToJByteArray(bytes);
      final output = jni.JByteArray(cipher!.getOutputSize(bytes.length))
        ..releasedBy(arena);
      final outputLength = cipher.doFinal$4(input, 0, bytes.length, output);
      return output.copyToDartBytes(length: outputLength);
    });
  } on OperationError {
    rethrow;
  } on jni.JThrowable catch (e) {
    final message = e.message;
    e.release();
    throw operationError('JCA Cipher($_aesCbcTransformation) failed: $message');
  } finally {
    cipher?.release();
  }
}

Stream<Uint8List> _aesCbcEncryptDecryptStream(
  Uint8List keyData,
  Stream<List<int>> data,
  List<int> iv,
  bool isEncrypt,
) async* {
  final arena = jni.Arena();
  Cipher? cipher;
  try {
    cipher = _createAesCbcCipher(keyData, _asUint8List(iv), isEncrypt);
    final inputBuffer = jni.JByteArray(_defaultChunkSize)..releasedBy(arena);
    final outputBuffer = jni.JByteArray(cipher.getOutputSize(_defaultChunkSize))
      ..releasedBy(arena);

    await for (final chunk in data) {
      final bytes = _asUint8List(chunk);
      var offset = 0;
      while (offset < bytes.length) {
        final remaining = bytes.length - offset;
        final length = remaining < _defaultChunkSize
            ? remaining
            : _defaultChunkSize;

        inputBuffer.setRange(0, length, bytes, offset);
        final outputLength = cipher.update$2(
          inputBuffer,
          0,
          length,
          outputBuffer,
        );
        if (outputLength > 0) {
          yield outputBuffer.copyToDartBytes(length: outputLength);
        }
        offset += length;
      }
    }

    final outputLength = cipher.doFinal$4(inputBuffer, 0, 0, outputBuffer);
    if (outputLength > 0) {
      yield outputBuffer.copyToDartBytes(length: outputLength);
    }
  } on OperationError {
    rethrow;
  } on jni.JThrowable catch (e) {
    final message = e.message;
    e.release();
    throw operationError('JCA Cipher($_aesCbcTransformation) failed: $message');
  } finally {
    cipher?.release();
    arena.releaseAll();
  }
}

final class _StaticAesCbcSecretKeyImpl implements StaticAesCbcSecretKeyImpl {
  const _StaticAesCbcSecretKeyImpl();

  @override
  Future<AesCbcSecretKeyImpl> importRawKey(List<int> keyData) async =>
      _AesCbcSecretKeyImpl(_aesImportRawKey(keyData));

  @override
  Future<AesCbcSecretKeyImpl> importJsonWebKey(
    Map<String, dynamic> jwk,
  ) async =>
      _AesCbcSecretKeyImpl(_aesImportJwkKey(jwk, expectedJwkAlgSuffix: 'CBC'));

  @override
  Future<AesCbcSecretKeyImpl> generateKey(int length) async =>
      _AesCbcSecretKeyImpl(_aesGenerateKey(length));
}

final class _AesCbcSecretKeyImpl implements AesCbcSecretKeyImpl {
  _AesCbcSecretKeyImpl(this._keyData);

  final Uint8List _keyData;

  @override
  String toString() => 'Instance of \'AesCbcSecretKey\'';

  @override
  Future<Uint8List> encryptBytes(List<int> data, List<int> iv) async =>
      _aesCbcEncryptDecryptBytes(_keyData, data, iv, true);

  @override
  Future<Uint8List> decryptBytes(List<int> data, List<int> iv) async =>
      _aesCbcEncryptDecryptBytes(_keyData, data, iv, false);

  @override
  Stream<Uint8List> encryptStream(Stream<List<int>> data, List<int> iv) =>
      _aesCbcEncryptDecryptStream(_keyData, data, iv, true);

  @override
  Stream<Uint8List> decryptStream(Stream<List<int>> data, List<int> iv) =>
      _aesCbcEncryptDecryptStream(_keyData, data, iv, false);

  @override
  Future<Uint8List> exportRawKey() async => Uint8List.fromList(_keyData);

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async =>
      _aesExportJwkKey(_keyData, jwkAlgSuffix: 'CBC');
}
