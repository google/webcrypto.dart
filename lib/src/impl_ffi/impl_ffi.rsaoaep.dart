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
    ffi.Pointer<ffi.IntPtr>,
    ffi.Pointer<ffi.Uint8>,
    int,
  )
      encryptOrDecryptFn,
  List<int> data, {
  List<int>? label,
}) async {
  final ctx = ssl.EVP_PKEY_CTX_new.invoke(key, ffi.nullptr);
  _checkOp(ctx.address != 0, fallback: 'allocation error');
  try {
    _checkOpIsOne(initFn(ctx));
    _checkOpIsOne(
      ssl.EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING),
    );
    _checkOpIsOne(ssl.EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md));
    _checkOpIsOne(ssl.EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md));

    // Copy and set label
    if (label != null && label.isNotEmpty) {
      final plabel = ssl.OPENSSL_malloc(label.length);
      _checkOp(plabel.address != 0);
      try {
        plabel.cast<ffi.Uint8>().asTypedList(label.length).setAll(0, label);
        _checkOpIsOne(ssl.EVP_PKEY_CTX_set0_rsa_oaep_label(
          ctx,
          plabel.cast(),
          label.length,
        ));
      } catch (_) {
        // Ownership is transferred to ctx by EVP_PKEY_CTX_set0_rsa_oaep_label
        ssl.OPENSSL_free(plabel);
        rethrow;
      }
    }

    return _withDataAsPointer(data, (ffi.Pointer<ffi.Uint8> input) {
      return _withAllocation(_sslAlloc<ffi.IntPtr>(),
          (ffi.Pointer<ffi.IntPtr> len) {
        len.value = 0;
        _checkOpIsOne(encryptOrDecryptFn(
          ctx,
          ffi.nullptr,
          len,
          input,
          data.length,
        ));
        return _withOutPointer(len.value, (ffi.Pointer<ffi.Uint8> output) {
          _checkOpIsOne(encryptOrDecryptFn(
            ctx,
            output,
            len,
            input,
            data.length,
          ));
        }).sublist(0, len.value);
      });
    });
  } finally {
    ssl.EVP_PKEY_CTX_free(ctx);
  }
}

class _RsaOaepPrivateKey implements RsaOaepPrivateKey {
  final _EvpPKey _key;
  final _Hash _hash;

  _RsaOaepPrivateKey(this._key, this._hash);

  @override
  Future<Uint8List> decryptBytes(List<int> data, {List<int>? label}) async {
    return _rsaOaepeEncryptOrDecryptBytes(
      _key,
      _hash.MD,
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
  Future<Uint8List> exportPkcs8Key() async {
    return _withOutCBB((cbb) {
      _checkOp(ssl.EVP_marshal_private_key.invoke(cbb, _key) == 1);
    });
  }
}

class _RsaOaepPublicKey implements RsaOaepPublicKey {
  final _EvpPKey _key;
  final _Hash _hash;

  _RsaOaepPublicKey(this._key, this._hash);

  @override
  Future<Uint8List> encryptBytes(List<int> data, {List<int>? label}) async {
    return _rsaOaepeEncryptOrDecryptBytes(
      _key,
      _hash.MD,
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
  Future<Uint8List> exportSpkiKey() async {
    return _withOutCBB((cbb) {
      _checkOp(ssl.EVP_marshal_public_key.invoke(cbb, _key) == 1);
    });
  }
}
