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

Future<Pbkdf2SecretKeyImpl> pbkdf2SecretKey_importRawKey(
    List<int> keyData) async {
  return _Pbkdf2SecretKeyImpl(Uint8List.fromList(keyData));
}

final class _StaticPbkdf2SecretKeyImpl implements StaticPbkdf2SecretKeyImpl {
  const _StaticPbkdf2SecretKeyImpl();

  @override
  Future<Pbkdf2SecretKeyImpl> importRawKey(List<int> keyData) {
    return pbkdf2SecretKey_importRawKey(keyData);
  }
}

final class _Pbkdf2SecretKeyImpl implements Pbkdf2SecretKeyImpl {
  final Uint8List _key;

  _Pbkdf2SecretKeyImpl(this._key);

  @override
  String toString() {
    return 'Instance of \'Pbkdf2SecretKey\'';
  }

  @override
  Future<Uint8List> deriveBits(
    int length,
    HashImpl hash,
    List<int> salt,
    int iterations,
  ) async {
    if (length < 0) {
      throw ArgumentError.value(length, 'length', 'must be positive integer');
    }
    final md = _HashImpl.fromHash(hash)._md;

    // Mirroring limitations in chromium:
    // https://chromium.googlesource.com/chromium/src/+/43d62c50b705f88c67b14539e91fd8fd017f70c4/components/webcrypto/algorithms/pbkdf2.cc#75
    if (length % 8 != 0) {
      throw operationError(
          'The length for PBKDF2 must be a multiple of 8 bits');
    }
    if (length == 0) {
      throw operationError(
          'A length of zero is not allowed Pbkdf2SecretKey.deriveBits');
    }
    if (iterations <= 0) {
      throw operationError(
          'Iterations <= 0 is not allowed for Pbkdf2SecretKey.deriveBits');
    }

    final lengthInBytes = length ~/ 8;

    return _Scope.async((scope) async {
      final out = scope<ffi.Uint8>(lengthInBytes);
      _checkOpIsOne(await _PKCS5_PBKDF2_HMAC(
        scope.dataAsPointer(_key),
        _key.length,
        scope.dataAsPointer(salt),
        salt.length,
        iterations,
        md,
        lengthInBytes,
        out,
      ));
      return out.copy(lengthInBytes);
    });
  }
}

/// Helper function to run `ssl.PKCS5_PBKDF2_HMAC` in an [Isolate]
/// using [Isolate.run].
///
/// This offloads the computationally expensive PBKDF2 operation to a
/// separate isolate to avoid blocking the main isolate.
///
/// Using this auxiliary function to wrap the call should reduce the risk that
/// unnecessary variables are copied into the closure passed to [Isolate.run].
Future<int> _PKCS5_PBKDF2_HMAC(
  ffi.Pointer<ffi.Char> key,
  int keyLength,
  ffi.Pointer<ffi.Uint8> salt,
  int saltLength,
  int iterations,
  ffi.Pointer<EVP_MD> md,
  int lengthInBytes,
  ffi.Pointer<ffi.Uint8> out,
) async =>
    await Isolate.run(
      () => ssl.PKCS5_PBKDF2_HMAC(
        key,
        keyLength,
        salt,
        saltLength,
        iterations,
        md,
        lengthInBytes,
        out,
      ),
      debugName: 'PKCS5_PBKDF2_HMAC',
    );
