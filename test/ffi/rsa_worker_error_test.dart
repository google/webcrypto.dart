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
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webcrypto/webcrypto.dart';
import 'package:webcrypto/src/third_party/boringssl/generated_bindings.dart'
    as ssl;

void main() {
  test('successful native operations clear the thread error queue', () {
    final rsa = ssl.RSA_new();
    final exponent = ssl.BN_new();
    try {
      expect(ssl.BN_set_word(exponent, 65537), 1);
      expect(ssl.RSA_generate_key_ex(rsa, 256, exponent, ffi.nullptr), 0);
      expect(ssl.ERR_peek_error(), isNot(0));

      fillRandomBytes(Uint8List(8));
      expect(ssl.ERR_peek_error(), 0);
    } finally {
      ssl.BN_free(exponent);
      ssl.RSA_free(rsa);
      ssl.ERR_clear_error();
    }
  });

  test(
    'RSA generation reports the native error from its worker isolate',
    () async {
      await expectLater(
        RsaOaepPrivateKey.generateKey(256, BigInt.from(65537), Hash.sha256),
        throwsA(
          isA<OperationError>().having(
            (error) => error.toString(),
            'message',
            contains('error:'),
          ),
        ),
      );
    },
  );
}
