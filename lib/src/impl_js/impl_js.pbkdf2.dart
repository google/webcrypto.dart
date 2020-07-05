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

final _pbkdf2AlgorithmName = 'PBKDF2';

Future<Pbkdf2SecretKey> pbkdf2SecretKey_importRawKey(List<int> keyData) async {
  return _Pbkdf2SecretKey(await _importKey(
    'raw',
    keyData,
    subtle.Algorithm(name: _pbkdf2AlgorithmName),
    _usagesDeriveBits,
    'secret',
    // Unlike all other key types it makes no sense to HkdfSecretKey to be
    // exported, and indeed webcrypto requires `extractable: false`.
    extractable: false,
  ));
}

class _Pbkdf2SecretKey implements Pbkdf2SecretKey {
  final subtle.CryptoKey _key;
  _Pbkdf2SecretKey(this._key);

  @override
  Future<Uint8List> deriveBits(
    int length,
    Hash hash,
    List<int> salt,
    int iterations,
  ) async {
    ArgumentError.checkNotNull(length, 'length');
    ArgumentError.checkNotNull(salt, 'salt');
    ArgumentError.checkNotNull(iterations, 'iterations');
    return await _deriveBits(
      subtle.Algorithm(
        name: _pbkdf2AlgorithmName,
        hash: _getHashAlgorithm(hash),
        salt: Uint8List.fromList(salt),
        iterations: iterations,
      ),
      _key,
      length,
    );
  }
}
