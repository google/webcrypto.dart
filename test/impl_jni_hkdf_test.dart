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

  test('JCA HKDF-SHA-256 matches RFC 5869 test case 1', () async {
    final key = await jni_impl.webCryptImpl.hkdfSecretKey.importRawKey(
      Uint8List(22)..fillRange(0, 22, 0x0b),
    );
    final derived = await key.deriveBits(
      42 * 8,
      jni_impl.webCryptImpl.sha256,
      Uint8List.fromList(List<int>.generate(13, (i) => i)),
      Uint8List.fromList(List<int>.generate(10, (i) => 0xf0 + i)),
    );

    expect(
      base64Encode(derived),
      'PLJfJfqs1XqQQ09k0DYvKi0tCpDPGlpMXbAtVuzExb80AHII1biHGFhl',
    );
  }, skip: skipReason);

  test('JCA HKDF matches FFI for every supported hash', () async {
    final jniKey = await jni_impl.webCryptImpl.hkdfSecretKey.importRawKey(
      Uint8List.fromList([0, 1, 2, 0x80, 0xff]),
    );
    final ffiKey = await ffi_impl.webCryptImpl.hkdfSecretKey.importRawKey(
      Uint8List.fromList([0, 1, 2, 0x80, 0xff]),
    );
    final hashes = [
      (jni_impl.webCryptImpl.sha1, ffi_impl.webCryptImpl.sha1),
      (jni_impl.webCryptImpl.sha256, ffi_impl.webCryptImpl.sha256),
      (jni_impl.webCryptImpl.sha384, ffi_impl.webCryptImpl.sha384),
      (jni_impl.webCryptImpl.sha512, ffi_impl.webCryptImpl.sha512),
    ];

    for (final (jniHash, ffiHash) in hashes) {
      final actual = await jniKey.deriveBits(512, jniHash, const [], const []);
      final expected = await ffiKey.deriveBits(
        512,
        ffiHash,
        const [],
        const [],
      );
      expect(actual, expected);
    }
  }, skip: skipReason);

  test('JCA HKDF validates output length', () async {
    final jniKey = await jni_impl.webCryptImpl.hkdfSecretKey.importRawKey([1]);
    final ffiKey = await ffi_impl.webCryptImpl.hkdfSecretKey.importRawKey([1]);

    expect(
      await jniKey.deriveBits(
        255 * 32 * 8,
        jni_impl.webCryptImpl.sha256,
        const [],
        const [],
      ),
      await ffiKey.deriveBits(
        255 * 32 * 8,
        ffi_impl.webCryptImpl.sha256,
        const [],
        const [],
      ),
    );

    await expectLater(
      jniKey.deriveBits(7, jni_impl.webCryptImpl.sha256, const [], const []),
      throwsA(isA<OperationError>()),
    );
    await expectLater(
      jniKey.deriveBits(
        (255 * 32 + 1) * 8,
        jni_impl.webCryptImpl.sha256,
        const [],
        const [],
      ),
      throwsA(isA<OperationError>()),
    );
  }, skip: skipReason);
}
