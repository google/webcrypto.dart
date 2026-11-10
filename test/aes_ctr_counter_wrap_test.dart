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

void main() {
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
  });

  test('AES-CTR keeps large byte encryption length stable', () async {
    final key = await AesCtrSecretKey.importRawKey(Uint8List(16));
    final plaintext = Uint8List(4097);
    final counter = Uint8List(16);

    final ciphertext = await key.encryptBytes(plaintext, counter, 128);
    final decrypted = await key.decryptBytes(ciphertext, counter, 128);

    expect(ciphertext, hasLength(plaintext.length));
    expect(decrypted, equals(plaintext));
  });

  test('AES-CTR stream encryption matches large byte encryption', () async {
    final key = await AesCtrSecretKey.importRawKey(Uint8List(16));
    final plaintext = Uint8List(4097);
    final counter = Uint8List(16);

    final ciphertext = await key.encryptBytes(plaintext, counter, 128);
    final streamedCiphertext = await _collectBytes(
      key.encryptStream(Stream.value(plaintext), counter, 128),
    );

    expect(streamedCiphertext, equals(ciphertext));
  });

  test('AES-CTR byte operations leave inputs unchanged across wrap', () async {
    final key = await AesCtrSecretKey.importRawKey(Uint8List(16));
    final plaintext = Uint8List(8193);
    final original = Uint8List.fromList(plaintext);
    final counter = Uint8List(16)
      ..[14] = 0xff
      ..[15] = 0xff;
    final originalCounter = Uint8List.fromList(counter);
    final ciphertext = await key.encryptBytes(plaintext, counter, 16);
    expect(plaintext, equals(original));
    expect(counter, equals(originalCounter));
    final savedCiphertext = Uint8List.fromList(ciphertext);
    expect(await key.decryptBytes(ciphertext, counter, 16), equals(original));
    expect(ciphertext, equals(savedCiphertext));
    expect(counter, equals(originalCounter));
  });

  test('AES-CTR stream operations leave the counter unchanged', () async {
    final key = await AesCtrSecretKey.importRawKey(Uint8List(16));
    final plaintext = Uint8List(8193);
    final counter = Uint8List(16)
      ..[14] = 0xff
      ..[15] = 0xff;
    final originalCounter = Uint8List.fromList(counter);
    final expected = await key.encryptBytes(plaintext, counter, 16);
    final encrypted = await _collectBytes(
      key.encryptStream(Stream.value(plaintext), counter, 16),
    );
    expect(encrypted, equals(expected));
    expect(counter, equals(originalCounter));
    final decrypted = await _collectBytes(
      key.decryptStream(Stream.value(encrypted), counter, 16),
    );
    expect(decrypted, equals(plaintext));
    expect(counter, equals(originalCounter));
  });
}

Future<Uint8List> _collectBytes(Stream<List<int>> stream) async {
  final builder = BytesBuilder(copy: false);
  await for (final chunk in stream) {
    builder.add(chunk);
  }
  return builder.takeBytes();
}
