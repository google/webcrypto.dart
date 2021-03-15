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

Future<HkdfSecretKey> hkdfSecretKey_importRawKey(List<int> keyData) async {
  ArgumentError.checkNotNull(keyData, 'keyData');
  return _HkdfSecretKey(Uint8List.fromList(keyData));
}

class _HkdfSecretKey implements HkdfSecretKey {
  final Uint8List _key;

  _HkdfSecretKey(this._key);

  @override
  Future<Uint8List> deriveBits(
    int length,
    Hash hash,
    List<int> salt,
    List<int> info,
  ) async {
    ArgumentError.checkNotNull(length, 'length');
    ArgumentError.checkNotNull(hash, 'hash');
    ArgumentError.checkNotNull(salt, 'salt');
    ArgumentError.checkNotNull(info, 'info');
    if (length < 0) {
      throw ArgumentError.value(length, 'length', 'must be positive integer');
    }
    final md = _Hash.fromHash(hash).MD;

    // Mirroring limitations in chromium:
    // https://chromium.googlesource.com/chromium/src/+/43d62c50b705f88c67b14539e91fd8fd017f70c4/components/webcrypto/algorithms/hkdf.cc#74
    if (length % 8 != 0) {
      throw _OperationError('The length for HKDF must be a multiple of 8 bits');
    }

    final lengthInBytes = length ~/ 8;

    final scope = _Scope();
    try {
      return _withOutPointer(lengthInBytes, (ffi.Pointer<ffi.Uint8> out) {
        final r = ssl.HKDF(
          out,
          lengthInBytes,
          md,
          scope.dataAsPointer(_key),
          _key.length,
          scope.dataAsPointer(salt),
          salt.length,
          scope.dataAsPointer(info),
          info.length,
        );
        if (r != 1) {
          final packed_error = ssl.ERR_peek_error();
          if (ERR_GET_LIB(packed_error) == ERR_LIB_HKDF &&
              ERR_GET_REASON(packed_error) == HKDF_R_OUTPUT_TOO_LARGE) {
            ssl.ERR_clear_error();
            throw _OperationError(
              'Length specified for HkdfSecretKey.deriveBits is too long',
            );
          }
          _checkOpIsOne(r, fallback: 'HKDF key derivation failed');
        }
      });
    } finally {
      scope.release();
    }
  }
}
