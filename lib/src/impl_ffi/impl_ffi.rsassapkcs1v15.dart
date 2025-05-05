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

Future<RsaSsaPkcs1V15PrivateKeyImpl> rsassaPkcs1V15PrivateKey_importPkcs8Key(
  List<int> keyData,
  HashImpl hash,
) async {
  // Get hash first, to avoid a leak of EVP_PKEY if _HashImpl.fromHash throws
  final h = _HashImpl.fromHash(hash);
  return _RsaSsaPkcs1V15PrivateKeyImpl(_importPkcs8RsaPrivateKey(keyData), h);
}

Future<RsaSsaPkcs1V15PrivateKeyImpl> rsassaPkcs1V15PrivateKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  HashImpl hash,
) async {
  // Get hash first, to avoid a leak of EVP_PKEY if _HashImpl.fromHash throws
  final h = _HashImpl.fromHash(hash);
  return _RsaSsaPkcs1V15PrivateKeyImpl(
    _importJwkRsaPrivateOrPublicKey(
      JsonWebKey.fromJson(jwk),
      isPrivateKey: true,
      expectedUse: 'sig',
      expectedAlg: h.rsassaPkcs1V15JwkAlg,
    ),
    h,
  );
}

Future<KeyPair<RsaSsaPkcs1V15PrivateKeyImpl, RsaSsaPkcs1V15PublicKeyImpl>>
    rsassaPkcs1V15PrivateKey_generateKey(
  int modulusLength,
  BigInt publicExponent,
  HashImpl hash,
) async {
  // Get hash first, to avoid a leak of EVP_PKEY if _HashImpl.fromHash throws
  final h = _HashImpl.fromHash(hash);
  final keys = await _generateRsaKeyPair(modulusLength, publicExponent);
  return (
    privateKey: _RsaSsaPkcs1V15PrivateKeyImpl(keys.privateKey, h),
    publicKey: _RsaSsaPkcs1V15PublicKeyImpl(keys.publicKey, h),
  );
}

Future<RsaSsaPkcs1V15PublicKeyImpl> rsassaPkcs1V15PublicKey_importSpkiKey(
  List<int> keyData,
  HashImpl hash,
) async {
  // Get hash first, to avoid a leak of EVP_PKEY if _HashImpl.fromHash throws
  final h = _HashImpl.fromHash(hash);
  return _RsaSsaPkcs1V15PublicKeyImpl(_importSpkiRsaPublicKey(keyData), h);
}

Future<RsaSsaPkcs1V15PublicKeyImpl> rsassaPkcs1V15PublicKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  HashImpl hash,
) async {
  // Get hash first, to avoid a leak of EVP_PKEY if _HashImpl.fromHash throws
  final h = _HashImpl.fromHash(hash);
  return _RsaSsaPkcs1V15PublicKeyImpl(
    _importJwkRsaPrivateOrPublicKey(
      JsonWebKey.fromJson(jwk),
      isPrivateKey: false,
      expectedUse: 'sig',
      expectedAlg: h.rsassaPkcs1V15JwkAlg,
    ),
    h,
  );
}

final class _StaticRsaSsaPkcs1V15PrivateKeyImpl
    implements StaticRsaSsaPkcs1v15PrivateKeyImpl {
  const _StaticRsaSsaPkcs1V15PrivateKeyImpl();

  @override
  Future<RsaSsaPkcs1V15PrivateKeyImpl> importPkcs8Key(
    List<int> keyData,
    HashImpl hash,
  ) =>
      rsassaPkcs1V15PrivateKey_importPkcs8Key(keyData, hash);

  @override
  Future<RsaSsaPkcs1V15PrivateKeyImpl> importJsonWebKey(
    Map<String, dynamic> jwk,
    HashImpl hash,
  ) =>
      rsassaPkcs1V15PrivateKey_importJsonWebKey(jwk, hash);

  @override
  Future<(RsaSsaPkcs1V15PrivateKeyImpl, RsaSsaPkcs1V15PublicKeyImpl)>
      generateKey(
    int modulusLength,
    BigInt publicExponent,
    HashImpl hash,
  ) async {
    final KeyPair<RsaSsaPkcs1V15PrivateKeyImpl, RsaSsaPkcs1V15PublicKeyImpl>
        pair = await rsassaPkcs1V15PrivateKey_generateKey(
            modulusLength, publicExponent, hash);

    return (pair.privateKey, pair.publicKey);
  }
}

final class _RsaSsaPkcs1V15PrivateKeyImpl
    implements RsaSsaPkcs1V15PrivateKeyImpl {
  final _EvpPKey _key;
  final _HashImpl _hash;

  _RsaSsaPkcs1V15PrivateKeyImpl(this._key, this._hash);

  @override
  String toString() {
    return 'Instance of \'RsassaPkcs1V15PrivateKey\'';
  }

  @override
  Future<Uint8List> signBytes(List<int> data) => signStream(Stream.value(data));

  @override
  Future<Uint8List> signStream(Stream<List<int>> data) =>
      _signStream(_key, _hash._md, data, config: (ctx) {
        _checkOpIsOne(ssl.EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING));
      });

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async =>
      _exportJwkRsaPrivateOrPublicKey(
        _key,
        isPrivateKey: true,
        jwkAlg: _hash.rsassaPkcs1V15JwkAlg,
        jwkUse: 'sig',
      );

  @override
  Future<Uint8List> exportPkcs8Key() async => _exportPkcs8Key(_key);
}

final class _StaticRsaSsaPkcs1V15PublicKeyImpl
    implements StaticRsaSsaPkcs1v15PublicKeyImpl {
  const _StaticRsaSsaPkcs1V15PublicKeyImpl();

  @override
  Future<RsaSsaPkcs1V15PublicKeyImpl> importSpkiKey(
          List<int> keyData, HashImpl hash) =>
      rsassaPkcs1V15PublicKey_importSpkiKey(keyData, hash);

  @override
  Future<RsaSsaPkcs1V15PublicKeyImpl> importJsonWebKey(
          Map<String, dynamic> jwk, HashImpl hash) =>
      rsassaPkcs1V15PublicKey_importJsonWebKey(jwk, hash);
}

final class _RsaSsaPkcs1V15PublicKeyImpl
    implements RsaSsaPkcs1V15PublicKeyImpl {
  final _EvpPKey _key;
  final _HashImpl _hash;

  _RsaSsaPkcs1V15PublicKeyImpl(this._key, this._hash);

  @override
  Future<bool> verifyBytes(List<int> signature, List<int> data) =>
      verifyStream(signature, Stream.value(data));

  @override
  Future<bool> verifyStream(List<int> signature, Stream<List<int>> data) =>
      _verifyStream(_key, _hash._md, signature, data, config: (ctx) {
        _checkOpIsOne(ssl.EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING));
      });

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async =>
      _exportJwkRsaPrivateOrPublicKey(
        _key,
        isPrivateKey: false,
        jwkAlg: _hash.rsassaPkcs1V15JwkAlg,
        jwkUse: 'sig',
      );

  @override
  Future<Uint8List> exportSpkiKey() async => _exportSpkiKey(_key);
}
