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

const _hkdfAlgorithmName = 'HKDF';

Future<HkdfSecretKeyImpl> hkdfSecretKey_importRawKey(List<int> keyData) async {
  return _HkdfSecretKeyImpl(await _importKey(
    'raw',
    keyData,
    const subtle.Algorithm(name: _hkdfAlgorithmName),
    _usagesDeriveBits,
    'secret',
    // Unlike all other key types it makes no sense to HkdfSecretKeyImpl to be
    // exported, and indeed webcrypto requires `extractable: false`.
    extractable: false,
  ));
}

final class _StaticHkdfSecretKeyImpl implements StaticHkdfSecretKeyImpl {
  const _StaticHkdfSecretKeyImpl();

  @override
  Future<HkdfSecretKeyImpl> importRawKey(List<int> keyData) async {
    return await hkdfSecretKey_importRawKey(keyData);
  }
}

final class _HkdfSecretKeyImpl implements HkdfSecretKeyImpl {
  final subtle.JSCryptoKey _key;
  _HkdfSecretKeyImpl(this._key);

  @override
  String toString() {
    return 'Instance of \'HkdfSecretKey\'';
  }

  @override
  Future<Uint8List> deriveBits(
    int length,
    Hash hash,
    List<int> salt,
    List<int> info,
  ) async {
    return await _deriveBits(
      subtle.Algorithm(
        name: _hkdfAlgorithmName,
        hash: _getHashAlgorithm(hash),
        salt: Uint8List.fromList(salt),
        info: Uint8List.fromList(info),
      ),
      _key,
      length,
    );
  }
}
