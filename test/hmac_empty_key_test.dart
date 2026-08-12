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

@TestOn('vm')
library;

import 'package:test/test.dart';
import 'package:webcrypto/webcrypto.dart';

final _throwsEmptyKey = throwsA(
  isA<FormatException>().having(
    (error) => error.message,
    'message',
    'HMAC key data must not be empty',
  ),
);

void main() {
  test('rejects an empty raw key', () async {
    await expectLater(
      HmacSecretKey.importRawKey(const [], Hash.sha256),
      _throwsEmptyKey,
    );
  });

  test('rejects an empty JWK key', () async {
    await expectLater(
      HmacSecretKey.importJsonWebKey(const {
        'kty': 'oct',
        'alg': 'HS256',
        'k': '',
      }, Hash.sha256),
      _throwsEmptyKey,
    );
  });
}
