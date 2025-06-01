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

Future<RsaPssPrivateKeyImpl> rsaPssPrivateKey_importPkcs8Key(
  List<int> keyData,
  HashImpl hash,
) async {
  // Validate and get hash function
  final h = _HashImpl.fromHash(hash);
  return _RsaPssPrivateKeyImpl(_importPkcs8RsaPrivateKey(keyData), h);
}

Future<RsaPssPrivateKeyImpl> rsaPssPrivateKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  HashImpl hash,
) async {
  // Validate and get hash function
  final h = _HashImpl.fromHash(hash);
  return _RsaPssPrivateKeyImpl(
    _importJwkRsaPrivateOrPublicKey(
      JsonWebKey.fromJson(jwk),
      isPrivateKey: true,
      expectedUse: 'sig',
      expectedAlg: h.rsaPssJwkAlg,
    ),
    h,
  );
}

Future<KeyPair<RsaPssPrivateKeyImpl, RsaPssPublicKeyImpl>>
    rsaPssPrivateKey_generateKey(
  int modulusLength,
  BigInt publicExponent,
  HashImpl hash,
) async {
  // Validate and get hash function
  final h = _HashImpl.fromHash(hash);
  final keys = await _generateRsaKeyPair(modulusLength, publicExponent);
  return (
    privateKey: _RsaPssPrivateKeyImpl(keys.privateKey, h),
    publicKey: _RsaPssPublicKeyImpl(keys.publicKey, h),
  );
}

Future<RsaPssPublicKeyImpl> rsaPssPublicKey_importSpkiKey(
  List<int> keyData,
  HashImpl hash,
) async {
  // Validate and get hash function
  final h = _HashImpl.fromHash(hash);
  return _RsaPssPublicKeyImpl(_importSpkiRsaPublicKey(keyData), h);
}

Future<RsaPssPublicKeyImpl> rsaPssPublicKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  HashImpl hash,
) async {
  // Validate and get hash function
  final h = _HashImpl.fromHash(hash);
  return _RsaPssPublicKeyImpl(
    _importJwkRsaPrivateOrPublicKey(JsonWebKey.fromJson(jwk),
        isPrivateKey: false, expectedUse: 'sig', expectedAlg: h.rsaPssJwkAlg),
    h,
  );
}

final class _StaticRsaPssPrivateKeyImpl implements StaticRsaPssPrivateKeyImpl {
  const _StaticRsaPssPrivateKeyImpl();

  @override
  Future<RsaPssPrivateKeyImpl> importPkcs8Key(
    List<int> keyData,
    HashImpl hash,
  ) async {
    return await rsaPssPrivateKey_importPkcs8Key(keyData, hash);
  }

  @override
  Future<RsaPssPrivateKeyImpl> importJsonWebKey(
    Map<String, dynamic> jwk,
    HashImpl hash,
  ) async {
    return await rsaPssPrivateKey_importJsonWebKey(jwk, hash);
  }

  @override
  Future<(RsaPssPrivateKeyImpl, RsaPssPublicKeyImpl)> generateKey(
    int modulusLength,
    BigInt publicExponent,
    HashImpl hash,
  ) async {
    final KeyPair<RsaPssPrivateKeyImpl, RsaPssPublicKeyImpl> keyPair =
        await rsaPssPrivateKey_generateKey(modulusLength, publicExponent, hash);

    return (keyPair.privateKey, keyPair.publicKey);
  }
}

final class _RsaPssPrivateKeyImpl implements RsaPssPrivateKeyImpl {
  final _EvpPKey _key;
  final _HashImpl _hash;

  _RsaPssPrivateKeyImpl(this._key, this._hash);

  @override
  String toString() {
    return 'Instance of \'RsaPssPrivateKey\'';
  }

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
      _exportJwkRsaPrivateOrPublicKey(_key,
          isPrivateKey: true, jwkUse: 'sig', jwkAlg: _hash.rsaPssJwkAlg);

  @override
  Future<Uint8List> exportPkcs8Key() async => _exportPkcs8Key(_key);
}

final class _StaticRsaPssPublicKeyImpl implements StaticRsaPssPublicKeyImpl {
  const _StaticRsaPssPublicKeyImpl();

  @override
  Future<RsaPssPublicKeyImpl> importSpkiKey(
    List<int> keyData,
    HashImpl hash,
  ) async {
    return await rsaPssPublicKey_importSpkiKey(keyData, hash);
  }

  @override
  Future<RsaPssPublicKeyImpl> importJsonWebKey(
    Map<String, dynamic> jwk,
    HashImpl hash,
  ) async {
    return await rsaPssPublicKey_importJsonWebKey(jwk, hash);
  }
}

final class _RsaPssPublicKeyImpl implements RsaPssPublicKeyImpl {
  final _EvpPKey _key;
  final _HashImpl _hash;

  _RsaPssPublicKeyImpl(this._key, this._hash);

  @override
  String toString() {
    return 'Instance of \'RsaPssPublicKey\'';
  }

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
      _exportJwkRsaPrivateOrPublicKey(_key,
          isPrivateKey: false, jwkUse: 'sig', jwkAlg: _hash.rsaPssJwkAlg);

  @override
  Future<Uint8List> exportSpkiKey() async => _exportSpkiKey(_key);
}
