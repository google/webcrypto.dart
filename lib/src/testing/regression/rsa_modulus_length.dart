// Copyright 2026 Google LLC
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

import 'package:webcrypto/webcrypto.dart';

import '../utils/utils.dart';

final _rsaKeyGenerators = <String, Future<void> Function(int)>{
  'RSA-OAEP': (modulusLength) async {
    await RsaOaepPrivateKey.generateKey(
      modulusLength,
      BigInt.from(65537),
      Hash.sha256,
    );
  },
  'RSA-PSS': (modulusLength) async {
    await RsaPssPrivateKey.generateKey(
      modulusLength,
      BigInt.from(65537),
      Hash.sha256,
    );
  },
  'RSASSA-PKCS1-v1_5': (modulusLength) async {
    await RsassaPkcs1V15PrivateKey.generateKey(
      modulusLength,
      BigInt.from(65537),
      Hash.sha256,
    );
  },
};

List<({String name, Future<void> Function() test})> tests() => [
  for (final MapEntry(key: algorithm, value: generateKey)
      in _rsaKeyGenerators.entries)
    for (final modulusLength in [-1, 0x100000000])
      (
        name: '$algorithm rejects modulusLength $modulusLength',
        test: () async {
          Object? error;
          try {
            await generateKey(modulusLength);
          } catch (e) {
            error = e;
          }
          check(
            error is ArgumentError,
            'Expected ArgumentError for modulusLength $modulusLength, '
            'got $error',
          );
        },
      ),
];
