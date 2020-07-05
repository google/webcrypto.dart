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

part of impl_js;

final _hkdfAlgorithmName = 'HKDF';

Future<HkdfSecretKey> hkdfSecretKey_importRawKey(List<int> keyData) async {
  return _HkdfSecretKey(await _importKey(
    'raw',
    keyData,
    subtle.Algorithm(name: _hkdfAlgorithmName),
    _usagesDeriveBits,
    'secret',
    // Unlike all other key types it makes no sense to HkdfSecretKey to be
    // exported, and indeed webcrypto requires `extractable: false`.
    extractable: false,
  ));
}

class _HkdfSecretKey implements HkdfSecretKey {
  final subtle.CryptoKey _key;
  _HkdfSecretKey(this._key);

  @override
  Future<Uint8List> deriveBits(
    int length,
    Hash hash,
    List<int> salt,
    List<int> info,
  ) async {
    ArgumentError.checkNotNull(length, 'length');
    ArgumentError.checkNotNull(salt, 'salt');
    ArgumentError.checkNotNull(info, 'info');
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
