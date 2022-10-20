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

String _rsaOaepJwkAlgFromHash(_Hash hash) {
  if (hash == Hash.sha1) {
    return 'RSA-OAEP';
  }
  if (hash == Hash.sha256) {
    return 'RSA-OAEP-256';
  }
  if (hash == Hash.sha384) {
    return 'RSA-OAEP-384';
  }
  if (hash == Hash.sha512) {
    return 'RSA-OAEP-512';
  }
  assert(false); // This should never happen!
  throw UnsupportedError('hash is not supported');
}

Future<RsaOaepPrivateKey> rsaOaepPrivateKey_importPkcs8Key(
  List<int> keyData,
  Hash hash,
) async {
  // Get hash first, to avoid a leak of EVP_PKEY if _Hash.fromHash throws
  final h = _Hash.fromHash(hash);
  return _RsaOaepPrivateKey(_importPkcs8RsaPrivateKey(keyData), h);
}

Future<RsaOaepPrivateKey> rsaOaepPrivateKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  Hash hash,
) async {
  // Get hash first, to avoid a leak of EVP_PKEY if _Hash.fromHash throws
  final h = _Hash.fromHash(hash);
  return _RsaOaepPrivateKey(
    _importJwkRsaPrivateOrPublicKey(
      JsonWebKey.fromJson(jwk),
      isPrivateKey: true,
      expectedUse: 'enc',
      expectedAlg: _rsaOaepJwkAlgFromHash(h),
    ),
    h,
  );
}

Future<KeyPair<RsaOaepPrivateKey, RsaOaepPublicKey>>
    rsaOaepPrivateKey_generateKey(
  int modulusLength,
  BigInt publicExponent,
  Hash hash,
) async {
  // Get hash first, to avoid a leak of EVP_PKEY if _Hash.fromHash throws
  final h = _Hash.fromHash(hash);
  final keys = _generateRsaKeyPair(modulusLength, publicExponent);
  return _KeyPair(
    privateKey: _RsaOaepPrivateKey(keys.privateKey, h),
    publicKey: _RsaOaepPublicKey(keys.publicKey, h),
  );
}

Future<RsaOaepPublicKey> rsaOaepPublicKey_importSpkiKey(
  List<int> keyData,
  Hash hash,
) async {
  // Get hash first, to avoid a leak of EVP_PKEY if _Hash.fromHash throws
  final h = _Hash.fromHash(hash);
  return _RsaOaepPublicKey(_importSpkiRsaPublicKey(keyData), h);
}

Future<RsaOaepPublicKey> rsaOaepPublicKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  Hash hash,
) async {
  // Get hash first, to avoid a leak of EVP_PKEY if _Hash.fromHash throws
  final h = _Hash.fromHash(hash);
  return _RsaOaepPublicKey(
    _importJwkRsaPrivateOrPublicKey(
      JsonWebKey.fromJson(jwk),
      isPrivateKey: false,
      expectedUse: 'enc',
      expectedAlg: _rsaOaepJwkAlgFromHash(h),
    ),
    h,
  );
}

/// Utility method to encrypt or decrypt with RSA-OAEP.
///
/// Expects:
///  * [initFn] as [ssl.EVP_PKEY_encrypt_init] or [ssl.EVP_PKEY_decrypt_init] ,
///  * [encryptOrDecryptFn] as [ssl.EVP_PKEY_encrypt] or [ssl.EVP_PKEY_decrypt].
Future<Uint8List> _rsaOaepeEncryptOrDecryptBytes(
  _EvpPKey key,
  ffi.Pointer<EVP_MD> md,
  // ssl.EVP_PKEY_encrypt_init
  int Function(ffi.Pointer<EVP_PKEY_CTX>) initFn,
  // ssl.EVP_PKEY_encrypt
  int Function(
    ffi.Pointer<EVP_PKEY_CTX>,
    ffi.Pointer<ffi.Uint8>,
    ffi.Pointer<ffi.Size>,
    ffi.Pointer<ffi.Uint8>,
    int,
  )
      encryptOrDecryptFn,
  List<int> data, {
  List<int>? label,
}) async {
  return _Scope.sync((scope) {
    final ctx = scope.create(
      () => ssl.EVP_PKEY_CTX_new.invoke(key, ffi.nullptr),
      ssl.EVP_PKEY_CTX_free,
    );
    _checkOpIsOne(initFn(ctx));
    _checkOpIsOne(ssl.EVP_PKEY_CTX_set_rsa_padding(
      ctx,
      RSA_PKCS1_OAEP_PADDING,
    ));
    _checkOpIsOne(ssl.EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md));
    _checkOpIsOne(ssl.EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md));

    // Copy and set label
    if (label != null && label.isNotEmpty) {
      final plabel = scope.dataAsPointer<ffi.Uint8>(label);
      _checkOpIsOne(ssl.EVP_PKEY_CTX_set0_rsa_oaep_label(
        ctx,
        plabel,
        label.length,
      ));
      scope.move(plabel);
    }

    final input = scope.dataAsPointer<ffi.Uint8>(data);
    final plen = scope<ffi.Size>();
    plen.value = 0;
    _checkOpIsOne(encryptOrDecryptFn(
      ctx,
      ffi.nullptr,
      plen,
      input,
      data.length,
    ));
    final out = scope<ffi.Uint8>(plen.value);
    _checkOpIsOne(encryptOrDecryptFn(
      ctx,
      out,
      plen,
      input,
      data.length,
    ));
    return out.copy(plen.value);
  });
}

class _RsaOaepPrivateKey implements RsaOaepPrivateKey {
  final _EvpPKey _key;
  final _Hash _hash;

  _RsaOaepPrivateKey(this._key, this._hash);

  @override
  Future<Uint8List> decryptBytes(List<int> data, {List<int>? label}) async {
    return _rsaOaepeEncryptOrDecryptBytes(
      _key,
      _hash._md,
      ssl.EVP_PKEY_decrypt_init,
      ssl.EVP_PKEY_decrypt,
      data,
      label: label,
    );
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async =>
      _exportJwkRsaPrivateOrPublicKey(
        _key,
        isPrivateKey: true,
        jwkUse: 'enc',
        jwkAlg: _rsaOaepJwkAlgFromHash(_hash),
      );

  @override
  Future<Uint8List> exportPkcs8Key() async => _exportPkcs8Key(_key);
}

class _RsaOaepPublicKey implements RsaOaepPublicKey {
  final _EvpPKey _key;
  final _Hash _hash;

  _RsaOaepPublicKey(this._key, this._hash);

  @override
  Future<Uint8List> encryptBytes(List<int> data, {List<int>? label}) async {
    return _rsaOaepeEncryptOrDecryptBytes(
      _key,
      _hash._md,
      ssl.EVP_PKEY_encrypt_init,
      ssl.EVP_PKEY_encrypt,
      data,
      label: label,
    );
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async =>
      _exportJwkRsaPrivateOrPublicKey(
        _key,
        isPrivateKey: false,
        jwkUse: 'enc',
        jwkAlg: _rsaOaepJwkAlgFromHash(_hash),
      );

  @override
  Future<Uint8List> exportSpkiKey() async => _exportSpkiKey(_key);
}
