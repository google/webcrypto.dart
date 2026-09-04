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

final class _StaticPbkdf2SecretKeyImpl implements StaticPbkdf2SecretKeyImpl {
  const _StaticPbkdf2SecretKeyImpl();

  @override
  Future<Pbkdf2SecretKeyImpl> importRawKey(List<int> keyData) async =>
      _Pbkdf2SecretKeyImpl(Uint8List.fromList(keyData));
}

final class _Pbkdf2SecretKeyImpl implements Pbkdf2SecretKeyImpl {
  _Pbkdf2SecretKeyImpl(this._keyData);

  final Uint8List _keyData;

  @override
  Future<Uint8List> deriveBits(
    int length,
    HashImpl hash,
    List<int> salt,
    int iterations,
  ) async {
    if (length < 0) {
      throw ArgumentError.value(
        length,
        'length',
        'must be a non-negative integer',
      );
    }
    if (length % 8 != 0) {
      throw operationError(
        'The length for PBKDF2 must be a multiple of 8 bits',
      );
    }
    if (iterations <= 0) {
      throw operationError(
        'Iterations <= 0 is not allowed for Pbkdf2SecretKey.deriveBits',
      );
    }

    final h = _hmacHashFromHash(hash);
    if (length == 0) {
      return Uint8List(0);
    }

    final password = Uint8List.fromList(_keyData);
    final saltData = Uint8List.fromList(salt);
    final lengthInBytes = length ~/ 8;
    return Isolate.run(
      () => _derivePbkdf2(
        password,
        saltData,
        iterations,
        lengthInBytes,
        h._hmacJcaName,
      ),
      debugName: 'JCA PBKDF2',
    );
  }
}

Uint8List _derivePbkdf2(
  Uint8List password,
  Uint8List salt,
  int iterations,
  int lengthInBytes,
  String hmacAlgorithm,
) {
  try {
    return jni.using((arena) {
      final algorithm = hmacAlgorithm.toJString()..releasedBy(arena);
      final mac = Mac.getInstance(algorithm);
      if (mac == null) {
        throw AssertionError('JCA Mac($hmacAlgorithm) returned null');
      }
      mac.releasedBy(arena);

      // HMAC with an empty key is equivalent to HMAC with one zero byte, but
      // JCA's SecretKeySpec rejects an empty key.
      final normalizedPassword = password.isEmpty ? Uint8List(1) : password;
      final javaPassword = arena.copyToJByteArray(normalizedPassword);
      final key = SecretKeySpec(javaPassword, algorithm)..releasedBy(arena);
      mac.init(key);

      final hashLength = mac.macLength;
      final blockCount = (lengthInBytes + hashLength - 1) ~/ hashLength;
      if (blockCount > 0xffffffff) {
        throw operationError(
          'Length specified for Pbkdf2SecretKey.deriveBits is too long',
        );
      }

      final javaSalt = arena.copyToJByteArray(salt);
      final counter = jni.JByteArray(4)..releasedBy(arena);
      final counterBytes = Uint8List(4);
      final u = jni.JByteArray(hashLength)..releasedBy(arena);
      final uBytes = Uint8List(hashLength);
      final block = Uint8List(hashLength);
      final output = Uint8List(lengthInBytes);

      // TODO: Batch this loop outside Dart after package-level Java helper
      // packaging is designed. The experimental path currently performs JNI
      // calls and one Java-to-Dart copy for every U value.
      var outputOffset = 0;
      for (var blockIndex = 1; blockIndex <= blockCount; blockIndex++) {
        counterBytes[0] = (blockIndex >>> 24) & 0xff;
        counterBytes[1] = (blockIndex >>> 16) & 0xff;
        counterBytes[2] = (blockIndex >>> 8) & 0xff;
        counterBytes[3] = blockIndex & 0xff;
        counter.setRange(0, 4, counterBytes);

        if (salt.isNotEmpty) {
          mac.update$1(javaSalt);
        }
        mac.update$1(counter);
        mac.doFinal$1(u, 0);
        u.copyRangeToDart(block, 0, hashLength);

        for (var iteration = 1; iteration < iterations; iteration++) {
          mac.update$1(u);
          mac.doFinal$1(u, 0);
          u.copyRangeToDart(uBytes, 0, hashLength);
          for (var i = 0; i < hashLength; i++) {
            block[i] ^= uBytes[i];
          }
        }

        final remaining = lengthInBytes - outputOffset;
        final blockLength = math.min(hashLength, remaining);
        output.setRange(outputOffset, outputOffset + blockLength, block);
        outputOffset += blockLength;
      }
      return output;
    });
  } on OperationError {
    rethrow;
  } on jni.JThrowable catch (e) {
    late final String message;
    try {
      message = e.message;
    } finally {
      e.release();
    }
    throw operationError('JCA PBKDF2 derivation failed: $message');
  }
}
