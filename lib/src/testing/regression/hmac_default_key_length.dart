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

List<({String name, Future<void> Function() test})> tests() => [
  for (final testCase in [
    (name: 'SHA-1', hash: Hash.sha1, expectedBytes: 64),
    (name: 'SHA-256', hash: Hash.sha256, expectedBytes: 64),
    (name: 'SHA-384', hash: Hash.sha384, expectedBytes: 128),
    (name: 'SHA-512', hash: Hash.sha512, expectedBytes: 128),
  ])
    (
      name: 'HMAC uses the Web Crypto default length for ${testCase.name}',
      test: () async {
        final key = await HmacSecretKey.generateKey(testCase.hash);
        final keyData = await key.exportRawKey();

        check(
          keyData.length == testCase.expectedBytes,
          'Expected a ${testCase.expectedBytes}-byte ${testCase.name} key',
        );
      },
    ),
  (
    name: 'HMAC explicit key length takes precedence',
    test: () async {
      final key = await HmacSecretKey.generateKey(Hash.sha512, length: 256);
      final keyData = await key.exportRawKey();

      check(keyData.length == 32, 'Expected a 32-byte HMAC key');
    },
  ),
];
