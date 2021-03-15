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

/// Convert [data] to [Uint8List] and zero to [lengthInBits] if given.
Uint8List _asUint8ListZeroedToBitLength(List<int> data, [int? lengthInBits]) {
  final buf = Uint8List.fromList(data);
  if (lengthInBits != null) {
    final startFrom = (lengthInBits / 8).floor();
    var remainder = (lengthInBits % 8).toInt();
    for (var i = startFrom; i < buf.length; i++) {
      // TODO: This passes tests, but I think this should be >> instead.. hmm...
      final mask = 0xff & (0xff << (8 - remainder));
      buf[i] = buf[i] & mask;
      remainder = 8;
    }
  }
  return buf;
}

String _hmacJwkAlgFromHash(_Hash hash) {
  if (hash == Hash.sha1) {
    return 'HS1';
  }
  if (hash == Hash.sha256) {
    return 'HS256';
  }
  if (hash == Hash.sha384) {
    return 'HS384';
  }
  if (hash == Hash.sha512) {
    return 'HS512';
  }
  assert(false); // This should never happen!
  throw UnsupportedError('hash is not supported');
}

Future<HmacSecretKey> hmacSecretKey_importRawKey(
  List<int> keyData,
  Hash hash, {
  int? length,
}) async {
  return _HmacSecretKey(
    _asUint8ListZeroedToBitLength(keyData, length),
    _Hash.fromHash(hash),
  );
}

Future<HmacSecretKey> hmacSecretKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  Hash hash, {
  int? length,
}) async {
  ArgumentError.checkNotNull(jwk, 'jwk');
  ArgumentError.checkNotNull(hash, 'hash');

  final h = _Hash.fromHash(hash);
  final k = JsonWebKey.fromJson(jwk);

  void checkJwk(bool condition, String prop, String message) =>
      _checkData(condition, message: 'JWK property "$prop" $message');

  checkJwk(k.kty == 'oct', 'kty', 'must be "oct"');
  checkJwk(k.k != null, 'k', 'must be present');
  checkJwk(k.use == null || k.use == 'sig', 'use', 'must be "sig", if present');
  final expectedAlg = _hmacJwkAlgFromHash(h);
  checkJwk(
    k.alg == null || k.alg == expectedAlg,
    'alg',
    'must be "$expectedAlg"',
  );

  final keyData = _jwkDecodeBase64UrlNoPadding(k.k!, 'k');

  return hmacSecretKey_importRawKey(keyData, hash, length: length);
}

Future<HmacSecretKey> hmacSecretKey_generateKey(Hash hash,
    {int? length}) async {
  final h = _Hash.fromHash(hash);
  length ??= ssl.EVP_MD_size(h.MD) * 8;
  final keyData = Uint8List((length / 8).ceil());
  fillRandomBytes(keyData);

  return _HmacSecretKey(
    _asUint8ListZeroedToBitLength(keyData, length),
    h,
  );
}

class _HmacSecretKey implements HmacSecretKey {
  final _Hash _hash;
  final Uint8List _keyData;

  _HmacSecretKey(this._keyData, this._hash);

  @override
  Future<Uint8List> signBytes(List<int> data) {
    ArgumentError.checkNotNull(data, 'data');

    return signStream(Stream.value(data));
  }

  @override
  Future<Uint8List> signStream(Stream<List<int>> data) async {
    final ctx = ssl.HMAC_CTX_new();
    _checkOp(ctx.address != 0, fallback: 'allocation error');
    try {
      _withDataAsPointer(_keyData, (ffi.Pointer<ffi.Void> p) {
        final n = _keyData.length;
        _checkOp(ssl.HMAC_Init_ex(ctx, p, n, _hash.MD, ffi.nullptr) == 1);
      });
      await _streamToUpdate(data, ctx, ssl.HMAC_Update);

      final size = ssl.HMAC_size(ctx);
      _checkOp(size > 0);
      return _withAllocation(_sslAlloc<ffi.Uint32>(),
          (ffi.Pointer<ffi.Uint32> psize) async {
        psize.value = size;
        return _withOutPointer(size, (ffi.Pointer<ffi.Uint8> p) {
          _checkOp(ssl.HMAC_Final(ctx, p, psize) == 1);
        }).sublist(0, psize.value);
      });
    } finally {
      ssl.HMAC_CTX_free(ctx);
    }
  }

  @override
  Future<bool> verifyBytes(List<int> signature, List<int> data) {
    ArgumentError.checkNotNull(signature, 'signature');
    ArgumentError.checkNotNull(data, 'data');

    return verifyStream(signature, Stream.value(data));
  }

  @override
  Future<bool> verifyStream(List<int> signature, Stream<List<int>> data) async {
    ArgumentError.checkNotNull(signature, 'signature');
    ArgumentError.checkNotNull(data, 'data');

    final other = await signStream(data);
    if (signature.length != other.length) {
      return false;
    }
    return _withDataAsPointer(signature, (ffi.Pointer<ffi.Void> s) {
      return _withDataAsPointer(other, (ffi.Pointer<ffi.Void> o) {
        return ssl.CRYPTO_memcmp(s, o, other.length) == 0;
      });
    });
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async {
    return JsonWebKey(
      kty: 'oct',
      use: 'sig',
      alg: _hmacJwkAlgFromHash(_hash),
      k: _jwkEncodeBase64UrlNoPadding(_keyData),
    ).toJson();
  }

  @override
  Future<Uint8List> exportRawKey() async {
    return Uint8List.fromList(_keyData);
  }
}
