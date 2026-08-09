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

final class _StaticHkdfSecretKeyImpl implements StaticHkdfSecretKeyImpl {
  const _StaticHkdfSecretKeyImpl();

  @override
  Future<HkdfSecretKeyImpl> importRawKey(List<int> keyData) async =>
      _HkdfSecretKeyImpl(Uint8List.fromList(keyData));
}

final class _HkdfSecretKeyImpl implements HkdfSecretKeyImpl {
  _HkdfSecretKeyImpl(this._keyData);

  final Uint8List _keyData;

  @override
  Future<Uint8List> deriveBits(
    int length,
    HashImpl hash,
    List<int> salt,
    List<int> info,
  ) async {
    if (length < 0) {
      throw ArgumentError.value(
        length,
        'length',
        'must be a non-negative integer',
      );
    }
    if (length % 8 != 0) {
      throw operationError('The length for HKDF must be a multiple of 8 bits');
    }

    final h = _hmacHashFromHash(hash);
    final lengthInBytes = length ~/ 8;

    try {
      return jni.using((arena) {
        final algorithm = h._hmacJcaName.toJString()..releasedBy(arena);
        final mac = Mac.getInstance(algorithm);
        if (mac == null) {
          throw AssertionError('JCA Mac(${h._hmacJcaName}) returned null');
        }
        mac.releasedBy(arena);

        final hashLength = mac.macLength;
        if (lengthInBytes > 255 * hashLength) {
          throw operationError(
            'Length specified for HkdfSecretKey.deriveBits is too long',
          );
        }
        if (lengthInBytes == 0) {
          return Uint8List(0);
        }

        // RFC 5869 defines an omitted salt as HashLen zero bytes. JCA's
        // SecretKeySpec rejects an empty key, so normalize an empty salt to
        // that equivalent representation before HKDF-Extract.
        final saltData = salt.isEmpty
            ? Uint8List(hashLength)
            : _asUint8List(salt);
        final javaSalt = arena.copyToJByteArray(saltData);
        final extractKey = SecretKeySpec(javaSalt, algorithm)
          ..releasedBy(arena);
        mac.init(extractKey);

        final inputKeyMaterial = arena.copyToJByteArray(_keyData);
        final pseudorandomKey = mac.doFinal$2(inputKeyMaterial);
        if (pseudorandomKey == null) {
          throw AssertionError('JCA HKDF-Extract returned null');
        }
        pseudorandomKey.releasedBy(arena);

        final expandKey = SecretKeySpec(pseudorandomKey, algorithm)
          ..releasedBy(arena);
        mac.init(expandKey);

        final javaInfo = arena.copyToJByteArray(_asUint8List(info));
        final block = jni.JByteArray(hashLength)..releasedBy(arena);
        final output = Uint8List(lengthInBytes);
        final blockCount = (lengthInBytes + hashLength - 1) ~/ hashLength;

        var outputOffset = 0;
        for (var blockIndex = 1; blockIndex <= blockCount; blockIndex++) {
          if (blockIndex > 1) {
            mac.update$1(block);
          }
          if (info.isNotEmpty) {
            mac.update$1(javaInfo);
          }
          mac.update(blockIndex);
          mac.doFinal$1(block, 0);

          final remaining = lengthInBytes - outputOffset;
          final blockLength = math.min(hashLength, remaining);
          block.copyRangeToDart(output, outputOffset, blockLength);
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
      throw operationError('JCA HKDF derivation failed: $message');
    }
  }
}
