// Copyright 2025 Google LLC
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

final class _StaticX25519PrivateKeyImpl implements StaticX25519PrivateKeyImpl {
  const _StaticX25519PrivateKeyImpl();

  @override
  Future<(X25519PrivateKeyImpl, X25519PublicKeyImpl)> generateKey() async {
    return _Scope.sync((scope) {
      final ctx = scope.create(
        () => ssl.EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, ffi.nullptr),
        ssl.EVP_PKEY_CTX_free,
      );
      final out = scope<ffi.Pointer<EVP_PKEY>>();
      _checkOpIsOne(ssl.EVP_PKEY_keygen_init(ctx));
      _checkOpIsOne(ssl.EVP_PKEY_keygen(ctx, out));
      final privKey = _EvpPKey.wrap(out.value);
      final pubKey = _newRawPublicKey(
        EVP_PKEY_X25519,
        _getRawPublicKey(privKey),
      );
      return (
        _X25519PrivateKeyImpl(privKey),
        _X25519PublicKeyImpl(pubKey),
      );
    });
  }

  @override
  Future<X25519PrivateKeyImpl> importJsonWebKey(
      Map<String, dynamic> jwk) async {
    final key = _crv25519ImportJsonWebKey(
      EVP_PKEY_X25519,
      JsonWebKey.fromJson(jwk),
      isPrivateKey: true,
      use: 'enc',
    );
    return _X25519PrivateKeyImpl(key);
  }

  @override
  Future<X25519PrivateKeyImpl> importPkcs8Key(List<int> keyData) async {
    return _Scope.sync((scope) {
      final k = ssl.EVP_parse_private_key(scope.createCBS(keyData));
      _checkData(k.address != 0, fallback: 'unable to parse key');
      final key = _EvpPKey.wrap(k);
      _checkData(ssl.EVP_PKEY_id.invoke(key) == EVP_PKEY_X25519,
          message: 'key is not an X25519 key');
      return _X25519PrivateKeyImpl(key);
    });
  }
}

final class _StaticX25519PublicKeyImpl implements StaticX25519PublicKeyImpl {
  const _StaticX25519PublicKeyImpl();

  @override
  Future<X25519PublicKeyImpl> importJsonWebKey(Map<String, dynamic> jwk) async {
    final key = _crv25519ImportJsonWebKey(
      EVP_PKEY_X25519,
      JsonWebKey.fromJson(jwk),
      isPrivateKey: false,
      use: 'enc',
    );
    return _X25519PublicKeyImpl(key);
  }

  @override
  Future<X25519PublicKeyImpl> importRawKey(List<int> keyData) async {
    final raw = Uint8List.fromList(keyData);
    final key = _newRawPublicKey(EVP_PKEY_X25519, raw);
    return _X25519PublicKeyImpl(key);
  }

  @override
  Future<X25519PublicKeyImpl> importSpkiKey(List<int> keyData) async {
    return _Scope.sync((scope) {
      final k = ssl.EVP_parse_public_key(scope.createCBS(keyData));
      _checkData(k.address != 0, fallback: 'unable to parse key');
      final key = _EvpPKey.wrap(k);
      _checkData(
        ssl.EVP_PKEY_id.invoke(key) == EVP_PKEY_X25519,
        message: 'key is not an X25519 public key',
      );
      return _X25519PublicKeyImpl(key);
    });
  }
}

final class _X25519PrivateKeyImpl implements X25519PrivateKeyImpl {
  final _EvpPKey _key;

  _X25519PrivateKeyImpl(this._key);

  @override
  Future<Uint8List> deriveBits(
    int length,
    X25519PublicKeyImpl publicKey,
  ) async {
    if (publicKey is! _X25519PublicKeyImpl) {
      throw ArgumentError.value(
        publicKey,
        'publicKey',
        'custom implementations of X25519PublicKeyImpl is not supported',
      );
    }

    if (length <= 0) {
      throw ArgumentError.value(length, 'length', 'must be positive');
    }

    const maxLength = _crv25519KeyLength * 8;
    if (length > maxLength) {
      throw operationError(
        'Length in X25519 key derivation is too large. '
        'Maximum allowed is $maxLength bits.',
      );
    }

    if (length == 0) {
      return Uint8List(0);
    }

    return _Scope.sync((scope) {
      final ctx = scope.create(
        () => ssl.EVP_PKEY_CTX_new.invoke(_key, ffi.nullptr),
        ssl.EVP_PKEY_CTX_free,
      );
      final out = scope<ffi.Uint8>(_crv25519KeyLength);
      final outLen = scope<ffi.Size>();
      outLen.value = _crv25519KeyLength;
      _checkOpIsOne(ssl.EVP_PKEY_derive_init(ctx));
      _checkOpIsOne(ssl.EVP_PKEY_derive_set_peer.invoke(ctx, publicKey._key));
      _checkOpIsOne(ssl.EVP_PKEY_derive(ctx, out, outLen));
      _checkOp(outLen.value == _crv25519KeyLength);
      Uint8List derived = out.copy(_crv25519KeyLength);

      final lengthBytes = (length / 8).ceil();
      derived = derived.sublist(0, lengthBytes);
      final zeroBits = lengthBytes * 8 - length;
      if (zeroBits > 0) {
        derived.last &= ((0xff << zeroBits) & 0xff);
      }
      return derived;
    });
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async {
    return JsonWebKey(
      kty: 'OKP',
      crv: 'X25519',
      x: _jwkEncodeBase64UrlNoPadding(_getRawPublicKey(_key)),
      d: _jwkEncodeBase64UrlNoPadding(_getRawPrivateKey(_key)),
    ).toJson();
  }

  @override
  Future<Uint8List> exportPkcs8Key() async => _exportPkcs8Key(_key);
}

final class _X25519PublicKeyImpl implements X25519PublicKeyImpl {
  final _EvpPKey _key;

  const _X25519PublicKeyImpl(this._key);

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async {
    return JsonWebKey(
      kty: 'OKP',
      crv: 'X25519',
      x: _jwkEncodeBase64UrlNoPadding(_getRawPublicKey(_key)),
    ).toJson();
  }

  @override
  Future<Uint8List> exportRawKey() async => _getRawPublicKey(_key);

  @override
  Future<Uint8List> exportSpkiKey() async => _exportSpkiKey(_key);
}
