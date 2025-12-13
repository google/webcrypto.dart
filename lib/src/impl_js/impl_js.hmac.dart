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

const _hmacAlgorithm = subtle.Algorithm(name: 'HMAC');

Future<HmacSecretKeyImpl> hmacSecretKey_importRawKey(
  List<int> keyData,
  HashImpl hash, {
  int? length,
}) async {
  return _HmacSecretKeyImpl(
    await _importKey(
      'raw',
      keyData,
      length == null
          ? subtle.Algorithm(name: 'HMAC', hash: _getHashAlgorithm(hash))
          : subtle.Algorithm(
              name: 'HMAC',
              hash: _getHashAlgorithm(hash),
              length: length,
            ),
      _usagesSignVerify,
      'secret',
    ),
  );
}

Future<HmacSecretKeyImpl> hmacSecretKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  HashImpl hash, {
  int? length,
}) async {
  return _HmacSecretKeyImpl(
    await _importJsonWebKey(
      jwk,
      length == null
          ? subtle.Algorithm(name: 'HMAC', hash: _getHashAlgorithm(hash))
          : subtle.Algorithm(
              name: 'HMAC',
              hash: _getHashAlgorithm(hash),
              length: length,
            ),
      _usagesSignVerify,
      'secret',
    ),
  );
}

Future<HmacSecretKeyImpl> hmacSecretKey_generateKey(
  HashImpl hash, {
  int? length,
}) async {
  return _HmacSecretKeyImpl(
    await _generateKey(
      length == null
          ? subtle.Algorithm(name: 'HMAC', hash: _getHashAlgorithm(hash))
          : subtle.Algorithm(
              name: 'HMAC',
              hash: _getHashAlgorithm(hash),
              length: length,
            ),
      _usagesSignVerify,
      'secret',
    ),
  );
}

final class _StaticHmacSecretKeyImpl implements StaticHmacSecretKeyImpl {
  const _StaticHmacSecretKeyImpl();

  @override
  Future<HmacSecretKeyImpl> importRawKey(
    List<int> keyData,
    HashImpl hash, {
    int? length,
  }) {
    return hmacSecretKey_importRawKey(keyData, hash, length: length);
  }

  @override
  Future<HmacSecretKeyImpl> importJsonWebKey(
    Map<String, dynamic> jwk,
    HashImpl hash, {
    int? length,
  }) {
    return hmacSecretKey_importJsonWebKey(jwk, hash, length: length);
  }

  @override
  Future<HmacSecretKeyImpl> generateKey(HashImpl hash, {int? length = 32}) {
    return hmacSecretKey_generateKey(hash, length: length);
  }
}

final class _HmacSecretKeyImpl implements HmacSecretKeyImpl {
  final subtle.JSCryptoKey _key;
  _HmacSecretKeyImpl(this._key);

  @override
  String toString() {
    return 'Instance of \'HmacSecretKey\'';
  }

  @override
  Future<Uint8List> signBytes(List<int> data) async {
    return await _sign(_hmacAlgorithm, _key, data);
  }

  @override
  Future<Uint8List> signStream(Stream<List<int>> data) async {
    return await signBytes(await _bufferStream(data));
  }

  @override
  Future<bool> verifyBytes(List<int> signature, List<int> data) async {
    return await _verify(_hmacAlgorithm, _key, signature, data);
  }

  @override
  Future<bool> verifyStream(List<int> signature, Stream<List<int>> data) async {
    return await verifyBytes(signature, await _bufferStream(data));
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async {
    return await _exportJsonWebKey(_key);
  }

  @override
  Future<Uint8List> exportRawKey() async {
    return await _exportKey('raw', _key);
  }
}
