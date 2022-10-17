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

abstract class _Hash implements Hash {
  const _Hash();

  factory _Hash.fromHash(Hash hash) {
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
  ffi.Pointer<EVP_MD> Function() get _algorithm;

  /// Get an instantiated [EVP_MD] for this hash algorithm.
  ffi.Pointer<EVP_MD> get _md {
    final md = _algorithm();
    _checkOp(md.address != 0, fallback: 'failed to instantiate hash algorithm');
    return md;
  }

  @override
  Future<Uint8List> digestBytes(List<int> data) =>
      digestStream(Stream.value(data));

  @override
  Future<Uint8List> digestStream(Stream<List<int>> data) {
    return _Scope.async((scope) async {
      final ctx = scope.create(ssl.EVP_MD_CTX_new, ssl.EVP_MD_CTX_free);
      // Initialize with hash function
      _checkOp(ssl.EVP_DigestInit(ctx, _md) == 1);

      // Stream data
      await _streamToUpdate(data, ctx, ssl.EVP_DigestUpdate);

      // Get size of the output buffer
      final size = ssl.EVP_MD_CTX_size(ctx);
      _checkOp(size > 0); // sanity check

      // Allocate output buffer and return output
      final out = scope<ffi.Uint8>(size);
      _checkOp(ssl.EVP_DigestFinal(ctx, out, ffi.nullptr) == 1);
      return out.copy(size);
    });
  }
}

class _Sha1 extends _Hash {
  const _Sha1();

  @override
  ffi.Pointer<EVP_MD> Function() get _algorithm => ssl.EVP_sha1;
}

class _Sha256 extends _Hash {
  const _Sha256();

  @override
  ffi.Pointer<EVP_MD> Function() get _algorithm => ssl.EVP_sha256;
}

class _Sha384 extends _Hash {
  const _Sha384();

  @override
  ffi.Pointer<EVP_MD> Function() get _algorithm => ssl.EVP_sha384;
}

class _Sha512 extends _Hash {
  const _Sha512();

  @override
  ffi.Pointer<EVP_MD> Function() get _algorithm => ssl.EVP_sha512;
}

const Hash sha1 = _Sha1();
const Hash sha256 = _Sha256();
const Hash sha384 = _Sha384();
const Hash sha512 = _Sha512();
// Note: Before adding new hash implementations, make sure to update all the
//       places that does if (hash == Hash.shaXXX) ...
