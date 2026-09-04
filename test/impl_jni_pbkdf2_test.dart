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

import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webcrypto/webcrypto.dart' show OperationError;
import 'package:webcrypto/src/impl_ffi/impl_ffi.dart' as ffi_impl;
import 'package:webcrypto/src/impl_jni/impl_jni.dart' as jni_impl;

import 'src/jni_test_setup.dart'
    if (dart.library.io) 'src/jni_test_setup_io.dart';

void main() {
  final skipReason = jniHelperSetupSkipReason;

  setUpAll(() {
    if (skipReason == null) {
      spawnJniForDesktopTests();
    }
  });

  test('JCA PBKDF2-HMAC-SHA-1 matches RFC 6070 vectors', () async {
    final key = await jni_impl.webCryptImpl.pbkdf2SecretKey.importRawKey(
      utf8.encode('password'),
    );
    final vectors = [
      (iterations: 1, expected: 'DGDID5YfDnHzqbUkr2ASBi/gN6Y='),
      (iterations: 2, expected: '6mwBTcctb4zNHtkqzh1B8NjeiVc='),
      (iterations: 4096, expected: 'SwB5AbdlSJq+rUnZJvch0GWkKcE='),
    ];

    for (final vector in vectors) {
      final derived = await key.deriveBits(
        160,
        jni_impl.webCryptImpl.sha1,
        utf8.encode('salt'),
        vector.iterations,
      );
      expect(base64Encode(derived), vector.expected);
    }
  }, skip: skipReason);

  test(
    'JCA PBKDF2 preserves arbitrary password bytes for every hash',
    () async {
      final password = Uint8List.fromList([0, 1, 2, 0x80, 0xff]);
      final salt = Uint8List.fromList([0xff, 0x80, 2, 1, 0]);
      final jniKey = await jni_impl.webCryptImpl.pbkdf2SecretKey.importRawKey(
        password,
      );
      final ffiKey = await ffi_impl.webCryptImpl.pbkdf2SecretKey.importRawKey(
        password,
      );
      final hashes = [
        (jni_impl.webCryptImpl.sha1, ffi_impl.webCryptImpl.sha1),
        (jni_impl.webCryptImpl.sha256, ffi_impl.webCryptImpl.sha256),
        (jni_impl.webCryptImpl.sha384, ffi_impl.webCryptImpl.sha384),
        (jni_impl.webCryptImpl.sha512, ffi_impl.webCryptImpl.sha512),
      ];

      for (final (jniHash, ffiHash) in hashes) {
        final actual = await jniKey.deriveBits(512, jniHash, salt, 3);
        final expected = await ffiKey.deriveBits(512, ffiHash, salt, 3);
        expect(actual, expected);
      }
    },
    skip: skipReason,
  );

  test('JCA PBKDF2 supports empty password, salt, and output', () async {
    final jniKey = await jni_impl.webCryptImpl.pbkdf2SecretKey.importRawKey([]);
    final ffiKey = await ffi_impl.webCryptImpl.pbkdf2SecretKey.importRawKey([]);

    expect(
      await jniKey.deriveBits(256, jni_impl.webCryptImpl.sha256, const [], 2),
      await ffiKey.deriveBits(256, ffi_impl.webCryptImpl.sha256, const [], 2),
    );
    expect(
      await jniKey.deriveBits(0, jni_impl.webCryptImpl.sha256, const [], 1),
      isEmpty,
    );
  }, skip: skipReason);

  test('JCA PBKDF2 validates length and iterations', () async {
    final key = await jni_impl.webCryptImpl.pbkdf2SecretKey.importRawKey([1]);

    await expectLater(
      key.deriveBits(7, jni_impl.webCryptImpl.sha256, const [], 1),
      throwsA(isA<OperationError>()),
    );
    await expectLater(
      key.deriveBits(8, jni_impl.webCryptImpl.sha256, const [], 0),
      throwsA(isA<OperationError>()),
    );
  }, skip: skipReason);
}
