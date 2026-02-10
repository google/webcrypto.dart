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

part of 'impl_ffi.dart';

final class _StaticEd25519PrivateKeyImpl
    implements StaticEd25519PrivateKeyImpl {
  const _StaticEd25519PrivateKeyImpl();

  @override
  Future<(Ed25519PrivateKeyImpl, Ed25519PublicKeyImpl)> generateKey() async {
    return _Scope.sync((scope) {
      final ctx = scope.create(
        () => ssl.EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, ffi.nullptr),
        ssl.EVP_PKEY_CTX_free,
      );
      final out = scope<ffi.Pointer<EVP_PKEY>>();
      _checkOpIsOne(ssl.EVP_PKEY_keygen_init(ctx));
      _checkOpIsOne(ssl.EVP_PKEY_keygen(ctx, out));
      final privKey = _EvpPKey.wrap(out.value);
      final rawPubKey = _getRawPublicKey(privKey);
      final pubKey = _newRawPublicKey(EVP_PKEY_ED25519, rawPubKey);
      return (
        _Ed25519PrivateKeyImpl(privKey),
        _Ed25519PublicKeyImpl(pubKey),
      );
    });
  }

  @override
  Future<Ed25519PrivateKeyImpl> importJsonWebKey(
    Map<String, dynamic> jwk,
  ) async {
    final key = _crv25519ImportJsonWebKey(
      EVP_PKEY_ED25519,
      JsonWebKey.fromJson(jwk),
      isPrivateKey: true,
      use: 'sig',
      alg: {'Ed25519', 'EdDSA'},
    );
    return _Ed25519PrivateKeyImpl(key);
  }

  @override
  Future<Ed25519PrivateKeyImpl> importPkcs8Key(List<int> keyData) async {
    return _Scope.sync((scope) {
      final cbs = scope.createCBS(keyData);
      final k = ssl.EVP_parse_private_key(cbs);
      _checkOp(k.address != 0);
      final key = _EvpPKey.wrap(k);
      _checkData(ssl.EVP_PKEY_id.invoke(key) == EVP_PKEY_ED25519,
          message: 'key is not an Ed25519 private key');
      return _Ed25519PrivateKeyImpl(key);
    });
  }
}

final class _Ed25519PrivateKeyImpl implements Ed25519PrivateKeyImpl {
  final _EvpPKey _key;

  const _Ed25519PrivateKeyImpl(this._key);

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async {
    final x = _getRawPublicKey(_key);
    final d = _getRawPrivateKey(_key);
    return JsonWebKey(
      kty: 'OKP',
      crv: 'Ed25519',
      alg: 'Ed25519',
      x: _jwkEncodeBase64UrlNoPadding(x),
      d: _jwkEncodeBase64UrlNoPadding(d),
    ).toJson();
  }

  @override
  Future<Uint8List> exportPkcs8Key() async => _exportPkcs8Key(_key);

  @override
  Future<Uint8List> signBytes(List<int> data) async {
    return _Scope.sync((scope) {
      final ctx = scope.create(
        ssl.EVP_MD_CTX_new,
        ssl.EVP_MD_CTX_free,
      );
      _checkOpIsOne(ssl.EVP_DigestSignInit.invoke(
        ctx,
        ffi.nullptr,
        ffi.nullptr,
        ffi.nullptr,
        _key,
      ));
      final outLen = scope<ffi.Size>();
      final bytes = Uint8List.fromList(data);
      final pBytes = scope.dataAsPointer<ffi.Uint8>(bytes);
      _checkOpIsOne(ssl.EVP_DigestSign(
        ctx,
        ffi.nullptr,
        outLen,
        pBytes,
        bytes.length,
      ));
      final out = scope<ffi.Uint8>(outLen.value);
      _checkOpIsOne(ssl.EVP_DigestSign(
        ctx,
        out,
        outLen,
        scope.dataAsPointer(bytes),
        bytes.length,
      ));
      return out.copy(outLen.value);
    });
  }
}

final class _StaticEd25519PublicKeyImpl implements StaticEd25519PublicKeyImpl {
  const _StaticEd25519PublicKeyImpl();

  @override
  Future<Ed25519PublicKeyImpl> importJsonWebKey(
      Map<String, dynamic> jwk) async {
    final key = _crv25519ImportJsonWebKey(
      EVP_PKEY_ED25519,
      JsonWebKey.fromJson(jwk),
      isPrivateKey: false,
      use: 'sig',
      alg: {'Ed25519', 'EdDSA'},
    );
    return _Ed25519PublicKeyImpl(key);
  }

  @override
  Future<Ed25519PublicKeyImpl> importRawKey(List<int> keyData) async {
    final key = _newRawPublicKey(EVP_PKEY_ED25519, Uint8List.fromList(keyData));
    return _Ed25519PublicKeyImpl(key);
  }

  @override
  Future<Ed25519PublicKeyImpl> importSpkiKey(List<int> keyData) async {
    return _Scope.sync((scope) {
      final k = ssl.EVP_parse_public_key(scope.createCBS(keyData));
      _checkData(k.address != 0, fallback: 'unable to parse key');
      final key = _EvpPKey.wrap(k);
      _checkData(
        ssl.EVP_PKEY_id.invoke(key) == EVP_PKEY_ED25519,
        message: 'key is not an Ed25519 public key',
      );
      return _Ed25519PublicKeyImpl(key);
    });
  }
}

final class _Ed25519PublicKeyImpl implements Ed25519PublicKeyImpl {
  final _EvpPKey _key;

  const _Ed25519PublicKeyImpl(this._key);

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async {
    final x = _getRawPublicKey(_key);
    return JsonWebKey(
      kty: 'OKP',
      crv: 'Ed25519',
      alg: 'Ed25519',
      x: _jwkEncodeBase64UrlNoPadding(x),
    ).toJson();
  }

  @override
  Future<Uint8List> exportRawKey() async => _getRawPublicKey(_key);

  @override
  Future<Uint8List> exportSpkiKey() async => _exportSpkiKey(_key);

  @override
  Future<bool> verifyBytes(List<int> signature, List<int> data) async {
    return _Scope.sync((scope) {
      final ctx = scope.create(
        ssl.EVP_MD_CTX_new,
        ssl.EVP_MD_CTX_free,
      );
      _checkOpIsOne(ssl.EVP_DigestVerifyInit.invoke(
        ctx,
        ffi.nullptr,
        ffi.nullptr,
        ffi.nullptr,
        _key,
      ));
      final verified = ssl.EVP_DigestVerify(
        ctx,
        scope.dataAsPointer(signature),
        signature.length,
        scope.dataAsPointer(data),
        data.length,
      );
      if (verified != 1) {
        ssl.ERR_clear_error();
      }
      return verified == 1;
    });
  }
}
