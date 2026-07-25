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

import 'package:test/test.dart';
import 'package:webcrypto/webcrypto.dart';

void main() {
  group('HMAC default key length', () {
    for (final testCase in [
      (name: 'SHA-1', hash: Hash.sha1, expectedBits: 512),
      (name: 'SHA-256', hash: Hash.sha256, expectedBits: 512),
      (name: 'SHA-384', hash: Hash.sha384, expectedBits: 1024),
      (name: 'SHA-512', hash: Hash.sha512, expectedBits: 1024),
    ]) {
      test(testCase.name, () async {
        final key = await HmacSecretKey.generateKey(testCase.hash);

        expect(await key.exportRawKey(), hasLength(testCase.expectedBits ~/ 8));
      });
    }

    test('explicit length takes precedence', () async {
      final key = await HmacSecretKey.generateKey(Hash.sha512, length: 256);

      expect(await key.exportRawKey(), hasLength(32));
    });
  });
}
