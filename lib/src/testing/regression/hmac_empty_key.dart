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
  (
    name: 'HMAC rejects empty raw keys',
    test: () => _expectEmptyKeyRejected(
      HmacSecretKey.importRawKey(const [], Hash.sha256),
    ),
  ),
  (
    name: 'HMAC rejects empty JWK keys',
    test: () => _expectEmptyKeyRejected(
      HmacSecretKey.importJsonWebKey(const {
        'kty': 'oct',
        'alg': 'HS256',
        'k': '',
      }, Hash.sha256),
    ),
  ),
];

Future<void> _expectEmptyKeyRejected(Future<HmacSecretKey> import) async {
  try {
    await import;
  } on FormatException catch (error) {
    check(
      error.message == 'HMAC key data must not be empty',
      'Expected an empty HMAC key error',
    );
    return;
  }
  check(false, 'Expected an empty HMAC key to be rejected');
}
