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

import 'dart:ffi' as ffi;

import 'package:boring/bindings.dart' as ssl;
import 'package:test/test.dart';
import 'package:webcrypto/webcrypto.dart';

/// Leaves an `EC_R_UNKNOWN_GROUP` error on BoringSSL's error queue, like
/// another package using package:boring on this thread might.
void _leaveStaleError() {
  ssl.ERR_clear_error();
  expect(ssl.EC_KEY_new_by_curve_name(-1), equals(ffi.nullptr));
  expect(ssl.ERR_peek_error(), isNot(0));
}

void main() {
  tearDown(ssl.ERR_clear_error);

  test('errors left by other code are not reported for RSA imports', () async {
    _leaveStaleError();
    await expectLater(
      RsaOaepPrivateKey.importPkcs8Key([1, 2, 3], Hash.sha256),
      throwsA(
        isA<FormatException>().having(
          (e) => e.message,
          'message',
          allOf(contains('DECODE_ERROR'), isNot(contains('UNKNOWN_GROUP'))),
        ),
      ),
    );
    expect(ssl.ERR_peek_error(), equals(0));
  });

  test('errors left by other code are not reported for EC imports', () async {
    _leaveStaleError();
    await expectLater(
      EcdhPublicKey.importSpkiKey([1, 2, 3], EllipticCurve.p256),
      throwsA(
        isA<FormatException>().having(
          (e) => e.message,
          'message',
          isNot(contains('UNKNOWN_GROUP')),
        ),
      ),
    );
    expect(ssl.ERR_peek_error(), equals(0));
  });
}
