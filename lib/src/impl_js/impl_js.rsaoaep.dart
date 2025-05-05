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

part of 'impl_js.dart';

const _rsaOaepAlgorithmName = 'RSA-OAEP';

Future<RsaOaepPrivateKeyImpl> rsaOaepPrivateKey_importPkcs8Key(
  List<int> keyData,
  HashImpl hash,
) async {
  return _RsaOaepPrivateKeyImpl(await _importKey(
    'pkcs8',
    keyData,
    subtle.Algorithm(
      name: _rsaOaepAlgorithmName,
      hash: _getHashAlgorithm(hash),
    ),
    _usagesDecrypt,
    'private',
  ));
}

Future<RsaOaepPrivateKeyImpl> rsaOaepPrivateKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  HashImpl hash,
) async {
  return _RsaOaepPrivateKeyImpl(await _importJsonWebKey(
    jwk,
    subtle.Algorithm(
      name: _rsaOaepAlgorithmName,
      hash: _getHashAlgorithm(hash),
    ),
    _usagesDecrypt,
    'private',
  ));
}

Future<KeyPair<RsaOaepPrivateKeyImpl, RsaOaepPublicKeyImpl>>
    rsaOaepPrivateKey_generateKey(
  int modulusLength,
  BigInt publicExponent,
  HashImpl hash,
) async {
  final pair = await _generateKeyPair(
    subtle.Algorithm(
      name: _rsaOaepAlgorithmName,
      hash: _getHashAlgorithm(hash),
      publicExponent: _publicExponentAsBuffer(publicExponent),
      modulusLength: modulusLength,
    ),
    _usagesEncryptDecrypt,
  );
  return (
    privateKey: _RsaOaepPrivateKeyImpl(pair.privateKey),
    publicKey: _RsaOaepPublicKeyImpl(pair.publicKey),
  );
}

Future<RsaOaepPublicKeyImpl> rsaOaepPublicKey_importSpkiKey(
  List<int> keyData,
  HashImpl hash,
) async {
  return _RsaOaepPublicKeyImpl(await _importKey(
    'spki',
    keyData,
    subtle.Algorithm(
      name: _rsaOaepAlgorithmName,
      hash: _getHashAlgorithm(hash),
    ),
    _usagesEncrypt,
    'public',
  ));
}

Future<RsaOaepPublicKeyImpl> rsaOaepPublicKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  HashImpl hash,
) async {
  return _RsaOaepPublicKeyImpl(await _importJsonWebKey(
    jwk,
    subtle.Algorithm(
      name: _rsaOaepAlgorithmName,
      hash: _getHashAlgorithm(hash),
    ),
    _usagesEncrypt,
    'public',
  ));
}

final class _StaticRsaOaepPrivateKeyImpl
    implements StaticRsaOaepPrivateKeyImpl {
  const _StaticRsaOaepPrivateKeyImpl();

  @override
  Future<RsaOaepPrivateKeyImpl> importPkcs8Key(
      List<int> keyData, HashImpl hash) {
    return rsaOaepPrivateKey_importPkcs8Key(keyData, hash);
  }

  @override
  Future<RsaOaepPrivateKeyImpl> importJsonWebKey(
      Map<String, dynamic> jwk, HashImpl hash) {
    return rsaOaepPrivateKey_importJsonWebKey(jwk, hash);
  }

  @override
  Future<(RsaOaepPrivateKeyImpl, RsaOaepPublicKeyImpl)> generateKey(
      int modulusLength, BigInt publicExponent, HashImpl hash) async {
    final KeyPair<RsaOaepPrivateKeyImpl, RsaOaepPublicKeyImpl> keyPair =
        await rsaOaepPrivateKey_generateKey(
            modulusLength, publicExponent, hash);

    return (keyPair.privateKey, keyPair.publicKey);
  }
}

final class _RsaOaepPrivateKeyImpl implements RsaOaepPrivateKeyImpl {
  final subtle.JSCryptoKey _key;
  _RsaOaepPrivateKeyImpl(this._key);

  @override
  String toString() {
    return 'Instance of \'RsaOaepPrivateKeyImpl\'';
  }

  @override
  Future<Uint8List> decryptBytes(List<int> data, {List<int>? label}) async {
    return _decrypt(
      label == null
          ? const subtle.Algorithm(name: _rsaOaepAlgorithmName)
          : subtle.Algorithm(
              name: _rsaOaepAlgorithmName,
              label: Uint8List.fromList(label),
            ),
      _key,
      data,
    );
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async {
    return await _exportJsonWebKey(_key);
  }

  @override
  Future<Uint8List> exportPkcs8Key() async {
    return await _exportKey('pkcs8', _key);
  }
}

final class _StaticRsaOaepPublicKeyImpl implements StaticRsaOaepPublicKeyImpl {
  const _StaticRsaOaepPublicKeyImpl();

  @override
  Future<RsaOaepPublicKeyImpl> importSpkiKey(List<int> keyData, HashImpl hash) {
    return rsaOaepPublicKey_importSpkiKey(keyData, hash);
  }

  @override
  Future<RsaOaepPublicKeyImpl> importJsonWebKey(
      Map<String, dynamic> jwk, HashImpl hash) {
    return rsaOaepPublicKey_importJsonWebKey(jwk, hash);
  }
}

final class _RsaOaepPublicKeyImpl implements RsaOaepPublicKeyImpl {
  final subtle.JSCryptoKey _key;
  _RsaOaepPublicKeyImpl(this._key);

  @override
  String toString() {
    return 'Instance of \'RsaOaepPublicKeyImpl\'';
  }

  @override
  Future<Uint8List> encryptBytes(List<int> data, {List<int>? label}) async {
    return _encrypt(
      label == null
          ? const subtle.Algorithm(name: _rsaOaepAlgorithmName)
          : subtle.Algorithm(
              name: _rsaOaepAlgorithmName,
              label: Uint8List.fromList(label),
            ),
      _key,
      data,
    );
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async {
    return await _exportJsonWebKey(_key);
  }

  @override
  Future<Uint8List> exportSpkiKey() async {
    return await _exportKey('spki', _key);
  }
}
