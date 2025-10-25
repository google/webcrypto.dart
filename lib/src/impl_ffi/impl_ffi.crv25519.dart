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

const _crv25519KeyLength = 32;

String _crv25519FromType(int pkeyType) {
  switch (pkeyType) {
    case EVP_PKEY_X25519:
      return 'X25519';
    case EVP_PKEY_ED25519:
      return 'Ed25519';
  }
  throw operationError('internal error detecting curve');
}

_EvpPKey _newRawPrivateKey(int type, Uint8List keyData) {
  final crv = _crv25519FromType(type);

  _checkData(
    keyData.length == _crv25519KeyLength,
    message: '$crv private key should be $_crv25519KeyLength bytes',
  );

  return _Scope.sync((scope) {
    final bytes = scope.dataAsPointer<ffi.Uint8>(keyData);
    final key = ssl.EVP_PKEY_new_raw_private_key(
      type,
      ffi.nullptr,
      bytes,
      _crv25519KeyLength,
    );
    _checkOp(key.address != 0);
    return _EvpPKey.wrap(key);
  });
}

_EvpPKey _newRawPublicKey(int type, Uint8List keyData) {
  final crv = _crv25519FromType(type);

  _checkData(
    keyData.length == _crv25519KeyLength,
    message: '$crv public key should be $_crv25519KeyLength bytes',
  );

  return _Scope.sync((scope) {
    final bytes = scope.dataAsPointer<ffi.Uint8>(keyData);
    final key = ssl.EVP_PKEY_new_raw_public_key(
      type,
      ffi.nullptr,
      bytes,
      _crv25519KeyLength,
    );
    _checkOp(key.address != 0);
    return _EvpPKey.wrap(key);
  });
}

_EvpPKey _crv25519ImportJsonWebKey(
  int pkeyType,
  JsonWebKey jwk, {
  required bool isPrivateKey,
  required String use,
  Set<String> alg = const {},
}) {
  final crv = _crv25519FromType(pkeyType);

  _checkData(
    jwk.kty == 'OKP',
    message: 'expected an $crv key, JWK property "kty" must be "OKP"',
  );

  _checkData(
    jwk.x != null,
    message: 'expected an $crv key, JWK property "x" is missing',
  );

  _checkData(
    jwk.use == null || jwk.use == use,
    message: 'JWK property "use" should be "enc", if present',
  );

  _checkData(
    jwk.crv == crv,
    message: 'expected an $crv key, JWK property "crv" must be "$crv"',
  );

  final algs = alg.map((e) => '"$e"').join(' or ');
  _checkData(
    jwk.alg == null || alg.isEmpty || alg.contains(jwk.alg),
    message: 'expected an $crv key, JWK property "alg" must be $algs.',
  );

  final x = _jwkDecodeBase64UrlNoPadding(jwk.x!, 'x');
  _checkData(
    x.length == _crv25519KeyLength,
    message: 'JWK property "x" should be $_crv25519KeyLength bytes',
  );

  if (isPrivateKey) {
    _checkData(
      jwk.d != null,
      message: 'expected an $crv private key, JWK property "d" is missing',
    );

    final d = _jwkDecodeBase64UrlNoPadding(jwk.d!, 'd');
    _checkData(
      d.length == _crv25519KeyLength,
      message: 'JWK property "d" should be $_crv25519KeyLength bytes',
    );
    return _newRawPrivateKey(pkeyType, d);
  }

  _checkData(
    jwk.d == null,
    message: 'expected an $crv public key, JWK property "d" is present',
  );

  return _newRawPublicKey(pkeyType, x);
}
