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

import 'dart:async';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webcrypto/webcrypto.dart';

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

  test('AES-CTR 32-bit counter wrap does not carry into nonce', () async {
    final key = await AesCtrSecretKey.importRawKey(
      Uint8List.fromList(List<int>.generate(16, (i) => i)),
    );

    final counterA = Uint8List(16);
    counterA[12] = 0xff;
    counterA[13] = 0xff;
    counterA[14] = 0xff;
    counterA[15] = 0xff;

    final counterB = Uint8List(16);
    counterB[11] = 0x01;

    final ciphertextA = await key.encryptBytes(Uint8List(32), counterA, 32);
    final ciphertextB = await key.encryptBytes(Uint8List(16), counterB, 32);

    expect(ciphertextA.sublist(16, 32), isNot(equals(ciphertextB)));
  }, skip: skipReason);

  test('AES-CTR keeps large byte encryption length stable', () async {
    final key = await AesCtrSecretKey.importRawKey(Uint8List(16));
    final plaintext = Uint8List(4097);
    final counter = Uint8List(16);

    final ciphertext = await key.encryptBytes(plaintext, counter, 128);
    final decrypted = await key.decryptBytes(ciphertext, counter, 128);

    expect(ciphertext, hasLength(plaintext.length));
    expect(decrypted, equals(plaintext));
  }, skip: skipReason);

  test('AES-CTR stream encryption matches large byte encryption', () async {
    final key = await AesCtrSecretKey.importRawKey(Uint8List(16));
    final plaintext = Uint8List(4097);
    final counter = Uint8List(16);

    final ciphertext = await key.encryptBytes(plaintext, counter, 128);
    final streamedCiphertext = await _collectBytes(
      key.encryptStream(Stream.value(plaintext), counter, 128),
    );

    expect(streamedCiphertext, equals(ciphertext));
  }, skip: skipReason);
}

Future<Uint8List> _collectBytes(Stream<List<int>> stream) async {
  final builder = BytesBuilder(copy: false);
  await for (final chunk in stream) {
    builder.add(chunk);
  }
  return builder.takeBytes();
}
