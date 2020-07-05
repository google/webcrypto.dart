part of impl_ffi;

abstract class _Hash implements Hash {
  const _Hash();

  factory _Hash.fromHash(Hash hash) {
    ArgumentError.checkNotNull(hash, 'hash');

    if (hash is _Hash) {
      return hash;
    }
    throw ArgumentError.value(
      hash,
      'hash',
      'Custom implementations of Hash is not supported',
    );
  }

  @protected
  ffi.Pointer<ssl.EVP_MD> Function() get _algorithm;

  /// Get an instantiated [ssl.EVP_MD] for this hash algorithm.
  ffi.Pointer<ssl.EVP_MD> get MD {
    final md = _algorithm();
    _checkOp(md.address != 0, fallback: 'failed to instantiate hash algorithm');
    return md;
  }

  @override
  Future<Uint8List> digestBytes(List<int> data) {
    ArgumentError.checkNotNull(data, 'data');

    return digestStream(Stream.value(data));
  }

  @override
  Future<Uint8List> digestStream(Stream<List<int>> data) async {
    ArgumentError.checkNotNull(data, 'data');

    return await _withEVP_MD_CTX((ctx) async {
      _checkOp(ssl.EVP_DigestInit(ctx, MD) == 1);
      await _streamToUpdate(data, ctx, ssl.EVP_DigestUpdate);
      final size = ssl.EVP_MD_CTX_size(ctx);
      _checkOp(size > 0);
      return _withOutPointer(size, (ffi.Pointer<ssl.Bytes> p) {
        _checkOp(ssl.EVP_DigestFinal(ctx, p, ffi.nullptr) == 1);
      });
    });
  }
}

class _Sha1 extends _Hash {
  const _Sha1();

  @override
  ffi.Pointer<ssl.EVP_MD> Function() get _algorithm => ssl.EVP_sha1;
}

class _Sha256 extends _Hash {
  const _Sha256();

  @override
  ffi.Pointer<ssl.EVP_MD> Function() get _algorithm => ssl.EVP_sha256;
}

class _Sha384 extends _Hash {
  const _Sha384();

  @override
  ffi.Pointer<ssl.EVP_MD> Function() get _algorithm => ssl.EVP_sha384;
}

class _Sha512 extends _Hash {
  const _Sha512();

  @override
  ffi.Pointer<ssl.EVP_MD> Function() get _algorithm => ssl.EVP_sha512;
}

const Hash sha1 = _Sha1();
const Hash sha256 = _Sha256();
const Hash sha384 = _Sha384();
const Hash sha512 = _Sha512();
// Note: Before adding new hash implementations, make sure to update all the
//       places that does if (hash == Hash.shaXXX) ...
