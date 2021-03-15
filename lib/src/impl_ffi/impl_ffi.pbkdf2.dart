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

Future<Pbkdf2SecretKey> pbkdf2SecretKey_importRawKey(List<int> keyData) async {
  ArgumentError.checkNotNull(keyData, 'keyData');
  return _Pbkdf2SecretKey(Uint8List.fromList(keyData));
}

class _Pbkdf2SecretKey implements Pbkdf2SecretKey {
  final Uint8List _key;

  _Pbkdf2SecretKey(this._key);

  @override
  Future<Uint8List> deriveBits(
    int length,
    Hash hash,
    List<int> salt,
    int iterations,
  ) async {
    ArgumentError.checkNotNull(length, 'length');
    ArgumentError.checkNotNull(hash, 'hash');
    ArgumentError.checkNotNull(salt, 'salt');
    ArgumentError.checkNotNull(iterations, 'iterations');
    if (length < 0) {
      throw ArgumentError.value(length, 'length', 'must be positive integer');
    }
    final md = _Hash.fromHash(hash).MD;

    // Mirroring limitations in chromium:
    // https://chromium.googlesource.com/chromium/src/+/43d62c50b705f88c67b14539e91fd8fd017f70c4/components/webcrypto/algorithms/pbkdf2.cc#75
    if (length % 8 != 0) {
      throw _OperationError(
          'The length for PBKDF2 must be a multiple of 8 bits');
    }
    if (length == 0) {
      throw _OperationError(
          'A length of zero is not allowed Pbkdf2SecretKey.deriveBits');
    }
    if (iterations <= 0) {
      throw _OperationError(
          'Iterations <= 0 is not allowed for Pbkdf2SecretKey.deriveBits');
    }

    final lengthInBytes = length ~/ 8;

    final scope = _Scope();
    try {
      return _withOutPointer(lengthInBytes, (ffi.Pointer<ffi.Uint8> out) {
        _checkOpIsOne(ssl.PKCS5_PBKDF2_HMAC(
          scope.dataAsPointer(_key),
          _key.length,
          scope.dataAsPointer(salt),
          salt.length,
          iterations,
          md,
          lengthInBytes,
          out,
        ));
      });
    } finally {
      scope.release();
    }
  }
}
