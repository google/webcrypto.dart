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

part of impl_ffi;

String _rsassaPkcs1V15JwkAlgFromHash(_Hash hash) {
  if (hash == Hash.sha1) {
    return 'RS1';
  }
  if (hash == Hash.sha256) {
    return 'RS256';
  }
  if (hash == Hash.sha384) {
    return 'RS384';
  }
  if (hash == Hash.sha512) {
    return 'RS512';
  }
  assert(false); // This should never happen!
  throw UnsupportedError('hash is not supported');
}

Future<RsassaPkcs1V15PrivateKey> rsassaPkcs1V15PrivateKey_importPkcs8Key(
  List<int> keyData,
  Hash hash,
) async {
  // Get hash first, to avoid a leak of EVP_PKEY if _Hash.fromHash throws
  final h = _Hash.fromHash(hash);
  return _RsassaPkcs1V15PrivateKey(_importPkcs8RsaPrivateKey(keyData), h);
}

Future<RsassaPkcs1V15PrivateKey> rsassaPkcs1V15PrivateKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  Hash hash,
) async {
  // Get hash first, to avoid a leak of EVP_PKEY if _Hash.fromHash throws
  final h = _Hash.fromHash(hash);
  return _RsassaPkcs1V15PrivateKey(
    _importJwkRsaPrivateOrPublicKey(
      JsonWebKey.fromJson(jwk),
      isPrivateKey: true,
      expectedUse: 'sig',
      expectedAlg: _rsassaPkcs1V15JwkAlgFromHash(h),
    ),
    h,
  );
}

Future<KeyPair<RsassaPkcs1V15PrivateKey, RsassaPkcs1V15PublicKey>>
    rsassaPkcs1V15PrivateKey_generateKey(
  int modulusLength,
  BigInt publicExponent,
  Hash hash,
) async {
  // Get hash first, to avoid a leak of EVP_PKEY if _Hash.fromHash throws
  final h = _Hash.fromHash(hash);
  final keys = _generateRsaKeyPair(modulusLength, publicExponent);
  return _KeyPair(
    privateKey: _RsassaPkcs1V15PrivateKey(keys.privateKey, h),
    publicKey: _RsassaPkcs1V15PublicKey(keys.publicKey, h),
  );
}

Future<RsassaPkcs1V15PublicKey> rsassaPkcs1V15PublicKey_importSpkiKey(
  List<int> keyData,
  Hash hash,
) async {
  // Get hash first, to avoid a leak of EVP_PKEY if _Hash.fromHash throws
  final h = _Hash.fromHash(hash);
  return _RsassaPkcs1V15PublicKey(_importSpkiRsaPublicKey(keyData), h);
}

Future<RsassaPkcs1V15PublicKey> rsassaPkcs1V15PublicKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  Hash hash,
) async {
  // Get hash first, to avoid a leak of EVP_PKEY if _Hash.fromHash throws
  final h = _Hash.fromHash(hash);
  return _RsassaPkcs1V15PublicKey(
    _importJwkRsaPrivateOrPublicKey(
      JsonWebKey.fromJson(jwk),
      isPrivateKey: false,
      expectedUse: 'sig',
      expectedAlg: _rsassaPkcs1V15JwkAlgFromHash(h),
    ),
    h,
  );
}

class _RsassaPkcs1V15PrivateKey implements RsassaPkcs1V15PrivateKey {
  final _EvpPKey _key;
  final _Hash _hash;

  _RsassaPkcs1V15PrivateKey(this._key, this._hash);

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
        jwkAlg: _rsassaPkcs1V15JwkAlgFromHash(_hash),
        jwkUse: 'sig',
      );

  @override
  Future<Uint8List> exportPkcs8Key() async => _exportPkcs8Key(_key);
}

class _RsassaPkcs1V15PublicKey implements RsassaPkcs1V15PublicKey {
  final _EvpPKey _key;
  final _Hash _hash;

  _RsassaPkcs1V15PublicKey(this._key, this._hash);

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
        jwkAlg: _rsassaPkcs1V15JwkAlgFromHash(_hash),
        jwkUse: 'sig',
      );

  @override
  Future<Uint8List> exportSpkiKey() async => _exportSpkiKey(_key);
}
