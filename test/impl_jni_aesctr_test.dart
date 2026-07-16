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

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';
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

  test('JCA AES-128-CTR encrypts and decrypts a known vector', () async {
    final keyData = base64Decode('VPhdE6z4820SUnBmesDBSw==');
    final plaintext = base64Decode(
      'dXJpcyBxdWlzIG1hdHRpcyBtYXNzYS4gUGhhc2VsbHVzIGNvbnZhbGxp',
    );
    final counter = base64Decode('AAEECRAZJDFAUWR5kKnE4Q==');

    final key = await jni_impl.webCryptImpl.aesCtrSecretKey.importRawKey(
      keyData,
    );
    final ciphertext = await key.encryptBytes(plaintext, counter, 64);

    final ffiKey = await ffi_impl.webCryptImpl.aesCtrSecretKey.importRawKey(
      keyData,
    );
    expect(ciphertext, await ffiKey.encryptBytes(plaintext, counter, 64));
    expect(
      base64Encode(ciphertext),
      'LnHSulNxQ6y+Z2rC2g8QQURwQWrI53qMPajfaef3cA0jaL+yAd3syGfz',
    );
    expect(await key.decryptBytes(ciphertext, counter, 64), plaintext);
  }, skip: skipReason);

  test('JCA AES-256-CTR stream encryption matches FFI', () async {
    final keyData = base64Decode(
      'WngeqRJDQN8vkhSxSPAM5+XQKqKZTv90uur/A5sX4Zk=',
    );
    final chunks = [
      base64Decode('IG5pYmguCgpTZWQgbW9sbGlzIHNhcGllbiBpbiBncmF2aWRhIA=='),
      base64Decode('YXVjdG9yLiBBZW5lYW4gbmliaCB0b3J0bw=='),
    ];
    final counter = base64Decode('/v7+/v7+/v7+/v7+/v7+/g==');

    final key = await jni_impl.webCryptImpl.aesCtrSecretKey.importRawKey(
      keyData,
    );
    final ciphertext = await _collectBytes(
      key.encryptStream(Stream.fromIterable(chunks), counter, 9),
    );

    final ffiKey = await ffi_impl.webCryptImpl.aesCtrSecretKey.importRawKey(
      keyData,
    );
    final ffiCiphertext = await _collectBytes(
      ffiKey.encryptStream(Stream.fromIterable(chunks), counter, 9),
    );

    expect(ciphertext, ffiCiphertext);
    expect(
      base64Encode(ciphertext),
      'Nj5naY4AWDSbh3taXM4k2Ys7gDlJJSmE4rBS2TQkYXf0DcO7G9pov5EQEXrrKk/L'
      'jGITblQI1GkCi9ndwl4=',
    );
  }, skip: skipReason);

  test('JCA AES-CTR counter rollover preserves the nonce bits', () async {
    final keyData = base64Decode('mkHLvTc/F5evWm7OAMz1Ag==');
    final plaintext = base64Decode(
      'cwpjb21tb2RvIGF0IHNpdCBhbWV0IG1pLiBQZWxsZW50ZXNxdWUgdmVoaWN1bGEgbA==',
    );
    final counter = base64Decode('/v7+/v7+/v7+/v7+/v7+/g==');

    final key = await jni_impl.webCryptImpl.aesCtrSecretKey.importRawKey(
      keyData,
    );
    final ciphertext = await key.encryptBytes(plaintext, counter, 2);

    expect(
      base64Encode(ciphertext),
      '74m8tH2wT2MCrtw3Qr5SUTqfOPGUGzIeRnqB8psPFu4eujcjm2VgLv+LuJubZbrdkg==',
    );
    expect(await key.decryptBytes(ciphertext, counter, 2), plaintext);
  }, skip: skipReason);

  test('JCA AES-CTR rejects data that would reuse a counter block', () async {
    final key = await jni_impl.webCryptImpl.aesCtrSecretKey.importRawKey(
      Uint8List(16),
    );
    final counter = Uint8List(16)..fillRange(0, 16, 0xff);

    await expectLater(
      key.encryptBytes(Uint8List(65), counter, 2),
      throwsA(
        isA<FormatException>().having(
          (e) => e.message,
          'message',
          'input is too large for the counter length',
        ),
      ),
    );
  }, skip: skipReason);

  test('JCA AES-CTR exports and imports JSON Web Keys', () async {
    final keyData = Uint8List.fromList(List<int>.generate(16, (i) => i));
    final key = await jni_impl.webCryptImpl.aesCtrSecretKey.importRawKey(
      keyData,
    );

    final jwk = await key.exportJsonWebKey();
    expect(jwk['kty'], 'oct');
    expect(jwk['use'], 'enc');
    expect(jwk['alg'], 'A128CTR');
    expect(jwk['k'], 'AAECAwQFBgcICQoLDA0ODw');

    final imported = await jni_impl.webCryptImpl.aesCtrSecretKey
        .importJsonWebKey(jwk);
    expect(await imported.exportRawKey(), keyData);
  }, skip: skipReason);

  test('JCA AES-CTR generateKey creates 128 and 256 bit keys', () async {
    final key128 = await jni_impl.webCryptImpl.aesCtrSecretKey.generateKey(128);
    final key256 = await jni_impl.webCryptImpl.aesCtrSecretKey.generateKey(256);

    expect(await key128.exportRawKey(), hasLength(16));
    expect(await key256.exportRawKey(), hasLength(32));
  }, skip: skipReason);

  test('JCA AES-CTR rejects invalid counter arguments', () async {
    final key = await jni_impl.webCryptImpl.aesCtrSecretKey.importRawKey(
      Uint8List(16),
    );

    expect(
      () => key.encryptStream(Stream.value(Uint8List(16)), Uint8List(15), 64),
      throwsArgumentError,
    );
    expect(
      () => key.encryptStream(Stream.value(Uint8List(16)), Uint8List(16), 0),
      throwsArgumentError,
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
