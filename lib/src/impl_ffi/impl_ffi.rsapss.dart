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

String _rsaPssJwkAlgFromHash(_Hash hash) {
  if (hash == Hash.sha1) {
    return 'PS1';
  }
  if (hash == Hash.sha256) {
    return 'PS256';
  }
  if (hash == Hash.sha384) {
    return 'PS384';
  }
  if (hash == Hash.sha512) {
    return 'PS512';
  }
  assert(false); // This should never happen!
  throw UnsupportedError('hash is not supported');
}

Future<RsaPssPrivateKey> rsaPssPrivateKey_importPkcs8Key(
  List<int> keyData,
  Hash hash,
) async {
  // Validate and get hash function
  final h = _Hash.fromHash(hash);
  return _RsaPssPrivateKey(_importPkcs8RsaPrivateKey(keyData), h);
}

Future<RsaPssPrivateKey> rsaPssPrivateKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  Hash hash,
) async {
  // Validate and get hash function
  final h = _Hash.fromHash(hash);
  return _RsaPssPrivateKey(
    _importJwkRsaPrivateOrPublicKey(
      JsonWebKey.fromJson(jwk),
      isPrivateKey: true,
      expectedUse: 'sig',
      expectedAlg: _rsaPssJwkAlgFromHash(h),
    ),
    h,
  );
}

Future<KeyPair<RsaPssPrivateKey, RsaPssPublicKey>> rsaPssPrivateKey_generateKey(
  int modulusLength,
  BigInt publicExponent,
  Hash hash,
) async {
  // Validate and get hash function
  final h = _Hash.fromHash(hash);
  final keys = _generateRsaKeyPair(modulusLength, publicExponent);
  return _KeyPair(
    privateKey: _RsaPssPrivateKey(keys.privateKey, h),
    publicKey: _RsaPssPublicKey(keys.publicKey, h),
  );
}

Future<RsaPssPublicKey> rsaPssPublicKey_importSpkiKey(
  List<int> keyData,
  Hash hash,
) async {
  // Validate and get hash function
  final h = _Hash.fromHash(hash);
  return _RsaPssPublicKey(_importSpkiRsaPublicKey(keyData), h);
}

Future<RsaPssPublicKey> rsaPssPublicKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  Hash hash,
) async {
  // Validate and get hash function
  final h = _Hash.fromHash(hash);
  return _RsaPssPublicKey(
    _importJwkRsaPrivateOrPublicKey(
      JsonWebKey.fromJson(jwk),
      isPrivateKey: false,
      expectedUse: 'sig',
      expectedAlg: _rsaPssJwkAlgFromHash(h),
    ),
    h,
  );
}

class _RsaPssPrivateKey implements RsaPssPrivateKey {
  final _EvpPKey _key;
  final _Hash _hash;

  _RsaPssPrivateKey(this._key, this._hash);

  @override
  Future<Uint8List> signBytes(List<int> data, int saltLength) {
    return signStream(Stream.value(data), saltLength);
  }

  @override
  Future<Uint8List> signStream(Stream<List<int>> data, int saltLength) {
    if (saltLength < 0) {
      throw ArgumentError.value(
        saltLength,
        'saltLength',
        'must be a positive integer',
      );
    }

    return _signStream(_key, _hash._md, data, config: (ctx) {
      _checkOpIsOne(ssl.EVP_PKEY_CTX_set_rsa_padding(
        ctx,
        RSA_PKCS1_PSS_PADDING,
      ));
      _checkDataIsOne(ssl.EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, saltLength));
      _checkDataIsOne(ssl.EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, _hash._md));
    });
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async =>
      _exportJwkRsaPrivateOrPublicKey(
        _key,
        isPrivateKey: true,
        jwkUse: 'sig',
        jwkAlg: _rsaPssJwkAlgFromHash(_hash),
      );

  @override
  Future<Uint8List> exportPkcs8Key() async => _exportPkcs8Key(_key);
}

class _RsaPssPublicKey implements RsaPssPublicKey {
  final _EvpPKey _key;
  final _Hash _hash;

  _RsaPssPublicKey(this._key, this._hash);

  @override
  Future<bool> verifyBytes(
    List<int> signature,
    List<int> data,
    int saltLength,
  ) =>
      verifyStream(signature, Stream.value(data), saltLength);

  @override
  Future<bool> verifyStream(
    List<int> signature,
    Stream<List<int>> data,
    int saltLength,
  ) {
    if (saltLength < 0) {
      throw ArgumentError.value(
        saltLength,
        'saltLength',
        'must be a positive integer',
      );
    }

    return _verifyStream(_key, _hash._md, signature, data, config: (ctx) {
      _checkOpIsOne(ssl.EVP_PKEY_CTX_set_rsa_padding(
        ctx,
        RSA_PKCS1_PSS_PADDING,
      ));
      _checkDataIsOne(ssl.EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, saltLength));
      _checkDataIsOne(ssl.EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, _hash._md));
    });
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async =>
      _exportJwkRsaPrivateOrPublicKey(
        _key,
        isPrivateKey: false,
        jwkUse: 'sig',
        jwkAlg: _rsaPssJwkAlgFromHash(_hash),
      );

  @override
  Future<Uint8List> exportSpkiKey() async => _exportSpkiKey(_key);
}
