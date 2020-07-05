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
      return _withOutPointer(lengthInBytes, (ffi.Pointer<ssl.Bytes> out) {
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
          if (ssl.ERR_GET_LIB(packed_error) == ssl.ERR_LIB_HKDF &&
              ssl.ERR_GET_REASON(packed_error) == ssl.HKDF_R_OUTPUT_TOO_LARGE) {
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
