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

final _aesKeyGenerators = <String, Future<void> Function(int)>{
  'AES-CBC': (length) async {
    await AesCbcSecretKey.generateKey(length);
  },
  'AES-CTR': (length) async {
    await AesCtrSecretKey.generateKey(length);
  },
  'AES-GCM': (length) async {
    await AesGcmSecretKey.generateKey(length);
  },
};

List<({String name, Future<void> Function() test})> tests() => [
  for (final MapEntry(key: algorithm, value: generateKey)
      in _aesKeyGenerators.entries)
    for (final length in [-1, 64, 0x10000])
      (
        name: '$algorithm rejects key length $length',
        test: () async {
          Object? error;
          try {
            await generateKey(length);
          } catch (e) {
            error = e;
          }
          check(
            error is FormatException,
            'Expected FormatException for key length $length, got $error',
          );
        },
      ),
  for (final MapEntry(key: algorithm, value: generateKey)
      in _aesKeyGenerators.entries)
    (
      name: '$algorithm rejects unsupported 192-bit keys',
      test: () async {
        Object? error;
        try {
          await generateKey(192);
        } catch (e) {
          error = e;
        }
        check(
          error is UnsupportedError,
          'Expected UnsupportedError for a 192-bit key, got $error',
        );
      },
    ),
];
