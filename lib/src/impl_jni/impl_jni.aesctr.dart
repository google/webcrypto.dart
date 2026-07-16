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

const _aesCtrTransformation = 'AES/CTR/NoPadding';
const _aesBlockSize = 16;

Stream<Uint8List> _aesCtrEncryptDecrypt(
  Uint8List keyData,
  Stream<List<int>> data,
  Uint8List counter,
  int length,
  bool isEncrypt,
) async* {
  final initialCounter = Uint8List.fromList(counter);
  final counterValue = _parseAesCtrCounter(initialCounter, length);
  final counterValues = BigInt.one << length;
  var bytesUntilWraparound =
      (counterValues - counterValue) * BigInt.from(_aesBlockSize);
  var bytesAfterWraparound = counterValue * BigInt.from(_aesBlockSize);
  var isBeforeWraparound = true;

  final arena = jni.Arena();
  try {
    var cipher = _createAesCtrCipher(arena, keyData, initialCounter, isEncrypt);
    final inputBuffer = jni.JByteArray(_defaultChunkSize)..releasedBy(arena);
    final outputBuffer = jni.JByteArray(_defaultChunkSize)..releasedBy(arena);

    await for (final chunk in data) {
      final bytes = _asUint8List(chunk);
      var offset = 0;
      while (offset < bytes.length) {
        final remaining = bytes.length - offset;
        final segmentLength = isBeforeWraparound
            ? _minBigIntAndInt(bytesUntilWraparound, remaining)
            : remaining;

        if (isBeforeWraparound) {
          bytesUntilWraparound -= BigInt.from(segmentLength);
        } else if (bytesAfterWraparound < BigInt.from(segmentLength)) {
          throw const FormatException(
            'input is too large for the counter length',
          );
        } else {
          bytesAfterWraparound -= BigInt.from(segmentLength);
        }

        var consumed = 0;
        while (consumed < segmentLength) {
          final chunkLength = math.min(
            _defaultChunkSize,
            segmentLength - consumed,
          );
          inputBuffer.setRange(0, chunkLength, bytes, offset + consumed);
          final outputLength = cipher.update$2(
            inputBuffer,
            0,
            chunkLength,
            outputBuffer,
          );
          if (outputLength > 0) {
            yield outputBuffer.copyToDartBytes(length: outputLength);
          }
          consumed += chunkLength;
        }
        offset += segmentLength;

        if (isBeforeWraparound && bytesUntilWraparound == BigInt.zero) {
          final finalOutput = cipher.doFinal();
          if (finalOutput != null) {
            finalOutput.releasedBy(arena);
            if (finalOutput.length > 0) {
              yield finalOutput.copyToDartBytes();
            }
          }

          cipher = _createAesCtrCipher(
            arena,
            keyData,
            _wrapAesCtrCounter(initialCounter, length),
            isEncrypt,
          );
          isBeforeWraparound = false;
        }
      }
    }

    final finalOutput = cipher.doFinal();
    if (finalOutput != null) {
      finalOutput.releasedBy(arena);
      if (finalOutput.length > 0) {
        yield finalOutput.copyToDartBytes();
      }
    }
  } on jni.JThrowable catch (e) {
    throw _aesCtrOperationError(e);
  } finally {
    arena.releaseAll();
  }
}

Cipher _createAesCtrCipher(
  jni.Arena arena,
  Uint8List keyData,
  Uint8List counter,
  bool isEncrypt,
) {
  final algorithm = 'AES'.toJString()..releasedBy(arena);
  final transformation = _aesCtrTransformation.toJString()..releasedBy(arena);
  final keyBytes = arena.copyToJByteArray(keyData);
  final secretKey = SecretKeySpec(keyBytes, algorithm)..releasedBy(arena);
  final counterBytes = arena.copyToJByteArray(counter);
  final parameters = IvParameterSpec(counterBytes)..releasedBy(arena);

  final cipher = Cipher.getInstance(transformation);
  if (cipher == null) {
    throw operationError('JCA Cipher($_aesCtrTransformation) is unavailable');
  }
  cipher.releasedBy(arena);
  cipher.init$2(
    isEncrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE,
    secretKey,
    parameters,
  );
  return cipher;
}

BigInt _parseAesCtrCounter(Uint8List counter, int length) {
  final byteCount = (length + 7) ~/ 8;
  final start = counter.length - byteCount;
  final remainder = length % 8;

  var value = BigInt.zero;
  for (var i = start; i < counter.length; i++) {
    var byte = counter[i] & 0xff;
    if (i == start && remainder != 0) {
      byte &= (1 << remainder) - 1;
    }
    value = (value << 8) | BigInt.from(byte);
  }
  return value;
}

Uint8List _wrapAesCtrCounter(Uint8List counter, int length) {
  final wrapped = Uint8List.fromList(counter);
  final counterBytes = length ~/ 8;
  if (counterBytes > 0) {
    wrapped.fillRange(wrapped.length - counterBytes, wrapped.length, 0);
  }
  final remainder = length % 8;
  if (remainder != 0) {
    final index = wrapped.length - counterBytes - 1;
    wrapped[index] &= 0xff & (0xff << remainder);
  }
  return wrapped;
}

int _minBigIntAndInt(BigInt value, int limit) {
  // Avoid converting huge counter-space values, such as 2^128,
  // to int just to compare them with the current Dart chunk length.
  final bigLimit = BigInt.from(limit);
  return value < bigLimit ? value.toInt() : limit;
}

OperationError _aesCtrOperationError(jni.JThrowable throwable) {
  late final String message;
  try {
    message = throwable.message;
  } finally {
    throwable.release();
  }
  return operationError('JCA Cipher($_aesCtrTransformation) failed: $message');
}

final class _StaticAesCtrSecretKeyImpl implements StaticAesCtrSecretKeyImpl {
  const _StaticAesCtrSecretKeyImpl();

  @override
  Future<AesCtrSecretKeyImpl> importRawKey(List<int> keyData) async =>
      _AesCtrSecretKeyImpl(_aesImportRawKey(keyData));

  @override
  Future<AesCtrSecretKeyImpl> importJsonWebKey(
    Map<String, dynamic> jwk,
  ) async =>
      _AesCtrSecretKeyImpl(_aesImportJwkKey(jwk, expectedJwkAlgSuffix: 'CTR'));

  @override
  Future<AesCtrSecretKeyImpl> generateKey(int length) async =>
      _AesCtrSecretKeyImpl(_aesGenerateKey(length));
}

final class _AesCtrSecretKeyImpl implements AesCtrSecretKeyImpl {
  _AesCtrSecretKeyImpl(this._keyData);

  final Uint8List _keyData;

  @override
  Future<Uint8List> encryptBytes(
    List<int> data,
    List<int> counter,
    int length,
  ) async {
    _checkArguments(counter, length);
    return _bufferStream(encryptStream(Stream.value(data), counter, length));
  }

  @override
  Future<Uint8List> decryptBytes(
    List<int> data,
    List<int> counter,
    int length,
  ) async {
    _checkArguments(counter, length);
    return _bufferStream(decryptStream(Stream.value(data), counter, length));
  }

  @override
  Stream<Uint8List> encryptStream(
    Stream<List<int>> data,
    List<int> counter,
    int length,
  ) {
    _checkArguments(counter, length);
    return _aesCtrEncryptDecrypt(
      _keyData,
      data,
      Uint8List.fromList(counter),
      length,
      true,
    );
  }

  @override
  Stream<Uint8List> decryptStream(
    Stream<List<int>> data,
    List<int> counter,
    int length,
  ) {
    _checkArguments(counter, length);
    return _aesCtrEncryptDecrypt(
      _keyData,
      data,
      Uint8List.fromList(counter),
      length,
      false,
    );
  }

  @override
  Future<Uint8List> exportRawKey() async => Uint8List.fromList(_keyData);

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async =>
      _aesExportJwkKey(_keyData, jwkAlgSuffix: 'CTR');

  void _checkArguments(List<int> counter, int length) {
    if (counter.length != 16) {
      throw ArgumentError.value(counter, 'counter', 'must be 16 bytes');
    }
    if (length <= 0 || 128 < length) {
      throw ArgumentError.value(length, 'length', 'must be between 1 and 128');
    }
  }
}
