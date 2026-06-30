// Copyright 2020 Google LLC
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
import 'package:webcrypto/src/impl_interface/impl_interface.dart';
import 'package:webcrypto/src/impl_ffi/impl_ffi.dart' as ffi_impl;
import 'package:webcrypto/src/impl_jni/impl_jni.dart' as jni_impl;

import 'src/jni_test_setup.dart'
    if (dart.library.io) 'src/jni_test_setup_io.dart';

void main() {
  final skipReason = jniHelperSetupSkipReason;

  setUpAll(() {
    if (skipReason != null) {
      return;
    }

    spawnJniForDesktopTests();
  });

  test('JCA AES-128-GCM encrypts and decrypts a known vector', () async {
    final keyData = base64Decode('3nle6RpFx77jwrksoNUb1Q==');
    final iv = base64Decode('AAEECRAZJDFAUWR5kKnE4Q==');
    final plaintext = base64Decode(
      'dWx0cmljZXMKcG9zdWVyZSBjdWJpbGlhIEN1cmFlOyBBbGlxdWFtIHF1aXMgaGVu'
      'ZHJlcml0IGxhY3VzLgo=',
    );
    final expectedCiphertext = base64Decode(
      '4FNVScf36O/F5uUwqA7qSKbDAhCDHaxdvYZmpViAbEY2GE2kYS18TFRVhfbY82T2'
      'JHfqOhIuMStKtHPOkmaB3pThaKK84ARXFj0xIL0b',
    );

    final key = await jni_impl.webCryptImpl.aesGcmSecretKey.importRawKey(
      keyData,
    );
    final ciphertext = await key.encryptBytes(plaintext, iv);

    final ffiKey = await ffi_impl.webCryptImpl.aesGcmSecretKey.importRawKey(
      keyData,
    );
    final ffiCiphertext = await ffiKey.encryptBytes(plaintext, iv);

    expect(ciphertext, expectedCiphertext);
    expect(ciphertext, ffiCiphertext);
    expect(await key.decryptBytes(ciphertext, iv), plaintext);
  }, skip: skipReason);

  test('JCA AES-256-GCM supports additional data', () async {
    final keyData = base64Decode(
      'uIfV8fgL3cR69VFEZBwFVKZYAEWRGl3k6JlT6mGAd1o=',
    );
    final iv = base64Decode('AAEECRAZJDFAUWR5kKnE4Q==');
    final additionalData = base64Decode(
      'AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=',
    );
    final plaintext = base64Decode(
      'bnNlY3RldHVyCmFsaXF1ZXQsIGRvbG9yIGF1Z3VlIG1vbGVzdGk=',
    );

    final key = await jni_impl.webCryptImpl.aesGcmSecretKey.importRawKey(
      keyData,
    );
    final ciphertext = await key.encryptBytes(
      plaintext,
      iv,
      additionalData: additionalData,
    );

    final ffiKey = await ffi_impl.webCryptImpl.aesGcmSecretKey.importRawKey(
      keyData,
    );
    final ffiCiphertext = await ffiKey.encryptBytes(
      plaintext,
      iv,
      additionalData: additionalData,
    );

    expect(ciphertext, ffiCiphertext);
    expect(
      await key.decryptBytes(ciphertext, iv, additionalData: additionalData),
      plaintext,
    );

    final wrongAdditionalData = Uint8List.fromList(additionalData);
    wrongAdditionalData[0] ^= 0xff;
    await expectLater(
      key.decryptBytes(ciphertext, iv, additionalData: wrongAdditionalData),
      throwsA(isA<OperationError>()),
    );
  }, skip: skipReason);

  test('JCA AES-GCM exports and imports JSON Web Keys', () async {
    final keyData = Uint8List.fromList(List<int>.generate(32, (i) => i));
    final key = await jni_impl.webCryptImpl.aesGcmSecretKey.importRawKey(
      keyData,
    );

    final jwk = await key.exportJsonWebKey();
    expect(jwk['kty'], 'oct');
    expect(jwk['use'], 'enc');
    expect(jwk['alg'], 'A256GCM');

    final imported = await jni_impl.webCryptImpl.aesGcmSecretKey
        .importJsonWebKey(jwk);

    expect(await imported.exportRawKey(), keyData);
  }, skip: skipReason);

  test('JCA AES-GCM generateKey creates 128 and 256 bit keys', () async {
    final key128 = await jni_impl.webCryptImpl.aesGcmSecretKey.generateKey(128);
    final key256 = await jni_impl.webCryptImpl.aesGcmSecretKey.generateKey(256);

    expect(await key128.exportRawKey(), hasLength(16));
    expect(await key256.exportRawKey(), hasLength(32));
  }, skip: skipReason);
}
