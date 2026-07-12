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

  test('JCA AES-128-CBC encrypts and decrypts a known vector', () async {
    final keyData = base64Decode('nJ0IrxKwen1VN2/rfLsmmA==');
    final iv = base64Decode('AAEECRAZJDFAUWR5kKnE4Q==');
    final plaintext = base64Decode(
      'dmVzdGlidWx1bSBsdWN0dXMgZGlhbSwgcXVpcwppbnRlcmR1bSBsZW8gYWxpcXVh'
      'bSBhYy4gTnVuYyBhYyBtaSBpbiBs',
    );
    final expectedCiphertext = base64Decode(
      'MlBdzmsDQSRORkwayz7U9P7v87lgsVRRTrWsZi3qnWiqTW+m6K3KRQ4B1I1u+W7r'
      '/kBCBQt404253SV0DeIHNe/HUesVja7CB5jvJUQ6GmQ=',
    );

    final key = await jni_impl.webCryptImpl.aesCbcSecretKey.importRawKey(
      keyData,
    );
    final ciphertext = await key.encryptBytes(plaintext, iv);

    final ffiKey = await ffi_impl.webCryptImpl.aesCbcSecretKey.importRawKey(
      keyData,
    );
    final ffiCiphertext = await ffiKey.encryptBytes(plaintext, iv);

    expect(ciphertext, expectedCiphertext);
    expect(ciphertext, ffiCiphertext);
    expect(await key.decryptBytes(ciphertext, iv), plaintext);
  }, skip: skipReason);

  test('JCA AES-256-CBC stream encryption matches FFI', () async {
    final keyData = base64Decode(
      'b0y6+MqS0ShCvZiloJJAeG8ei8tVIN3OCYIdn1FN74o=',
    );
    final iv = base64Decode('AAEECRAZJDFAUWR5kKnE4Q==');
    final chunks = [
      utf8.encode('vestibulum vestibulum '),
      utf8.encode('luctus diam, quis '),
      utf8.encode('aliquam.'),
    ];

    final key = await jni_impl.webCryptImpl.aesCbcSecretKey.importRawKey(
      keyData,
    );
    final ciphertext = await _collectBytes(
      key.encryptStream(Stream.fromIterable(chunks), iv),
    );

    final ffiKey = await ffi_impl.webCryptImpl.aesCbcSecretKey.importRawKey(
      keyData,
    );
    final ffiCiphertext = await _collectBytes(
      ffiKey.encryptStream(Stream.fromIterable(chunks), iv),
    );

    expect(ciphertext, ffiCiphertext);
    expect(
      await _collectBytes(key.decryptStream(Stream.value(ciphertext), iv)),
      chunks.expand((chunk) => chunk),
    );
  }, skip: skipReason);

  test('JCA AES-CBC exports and imports JSON Web Keys', () async {
    final keyData = Uint8List.fromList(List<int>.generate(32, (i) => i));
    final key = await jni_impl.webCryptImpl.aesCbcSecretKey.importRawKey(
      keyData,
    );

    final jwk = await key.exportJsonWebKey();
    expect(jwk['kty'], 'oct');
    expect(jwk['use'], 'enc');
    expect(jwk['alg'], 'A256CBC');

    final imported = await jni_impl.webCryptImpl.aesCbcSecretKey
        .importJsonWebKey(jwk);

    expect(await imported.exportRawKey(), keyData);
  }, skip: skipReason);

  test('JCA AES-CBC generateKey creates 128 and 256 bit keys', () async {
    final key128 = await jni_impl.webCryptImpl.aesCbcSecretKey.generateKey(128);
    final key256 = await jni_impl.webCryptImpl.aesCbcSecretKey.generateKey(256);

    expect(await key128.exportRawKey(), hasLength(16));
    expect(await key256.exportRawKey(), hasLength(32));
  }, skip: skipReason);

  test('JCA AES-CBC rejects invalid IV length as ArgumentError', () async {
    final key = await jni_impl.webCryptImpl.aesCbcSecretKey.importRawKey(
      Uint8List(16),
    );

    await expectLater(
      key.encryptBytes(Uint8List(16), Uint8List(15)),
      throwsA(isA<ArgumentError>()),
    );
  }, skip: skipReason);

  test('JCA AES-CBC translates invalid padding to OperationError', () async {
    final keyData = base64Decode('nJ0IrxKwen1VN2/rfLsmmA==');
    final iv = base64Decode('AAEECRAZJDFAUWR5kKnE4Q==');
    final key = await jni_impl.webCryptImpl.aesCbcSecretKey.importRawKey(
      keyData,
    );
    final ciphertext = Uint8List.fromList(
      await key.encryptBytes(utf8.encode('padding check'), iv),
    );
    ciphertext[ciphertext.length - 1] ^= 0x01;

    await expectLater(
      key.decryptBytes(ciphertext, iv),
      throwsA(isA<OperationError>()),
    );
  }, skip: skipReason);
}

Future<Uint8List> _collectBytes(Stream<List<int>> stream) async {
  final builder = BytesBuilder(copy: false);
  await for (final chunk in stream) {
    builder.add(chunk);
  }
  return builder.takeBytes();
}
