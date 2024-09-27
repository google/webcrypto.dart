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

const _pbkdf2AlgorithmName = 'PBKDF2';

Future<Pbkdf2SecretKeyImpl> pbkdf2SecretKey_importRawKey(List<int> keyData) async {
  return _Pbkdf2SecretKeyImpl(await _importKey(
    'raw',
    keyData,
    const subtle.Algorithm(name: _pbkdf2AlgorithmName),
    _usagesDeriveBits,
    'secret',
    // Unlike all other key types it makes no sense to HkdfSecretKey to be
    // exported, and indeed webcrypto requires `extractable: false`.
    extractable: false,
  ));
}

final class _StaticPbkdf2SecretKeyImpl implements StaticPbkdf2SecretKeyImpl {
  const _StaticPbkdf2SecretKeyImpl();

  @override
  Future<Pbkdf2SecretKeyImpl> importRawKey(List<int> keyData) {
    return pbkdf2SecretKey_importRawKey(keyData);
  }
}

final class _Pbkdf2SecretKeyImpl implements Pbkdf2SecretKeyImpl {
  final subtle.JSCryptoKey _key;
  _Pbkdf2SecretKeyImpl(this._key);

  @override
  String toString() {
    return 'Instance of \'Pbkdf2SecretKey\'';
  }

  @override
  Future<Uint8List> deriveBits(
    int length,
    Hash hash,
    List<int> salt,
    int iterations,
  ) async {
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
