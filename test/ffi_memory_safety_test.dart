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
@Timeout(Duration(minutes: 3))
library;

import 'dart:async';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webcrypto/webcrypto.dart';

void main() {
  test('symmetric operations survive memory pressure', () async {
    for (var i = 0; i < 16; i++) {
      final message = _bytes(64 + i, i);
      final digest = await Hash.sha256.digestBytes(message);
      expect(digest, hasLength(32));

      final aesKeyData = _bytes(16, 100 + i);
      final aesKey = await AesGcmSecretKey.importRawKey(aesKeyData);
      final iv = _bytes(12, 200 + i);
      final additionalData = _bytes(8, 300 + i);
      final ciphertext = await aesKey.encryptBytes(
        message,
        iv,
        additionalData: additionalData,
      );
      final plaintext = await aesKey.decryptBytes(
        ciphertext,
        iv,
        additionalData: additionalData,
      );
      expect(plaintext, equals(message));
      expect(await aesKey.exportRawKey(), equals(aesKeyData));

      final aesJwk = await aesKey.exportJsonWebKey();
      final aesJwkKey = await AesGcmSecretKey.importJsonWebKey(aesJwk);
      expect(await aesJwkKey.exportRawKey(), equals(aesKeyData));

      final hmacKeyData = _bytes(32, 400 + i);
      final hmacKey = await HmacSecretKey.importRawKey(
        hmacKeyData,
        Hash.sha256,
      );
      final signature = await hmacKey.signBytes(message);
      expect(await hmacKey.verifyBytes(signature, message), isTrue);
      expect(await hmacKey.exportRawKey(), equals(hmacKeyData));

      final hmacJwk = await hmacKey.exportJsonWebKey();
      final hmacJwkKey = await HmacSecretKey.importJsonWebKey(
        hmacJwk,
        Hash.sha256,
      );
      expect(await hmacJwkKey.verifyBytes(signature, message), isTrue);

      if (i.isEven) {
        await _applyMemoryPressure();
      }
    }
  });

  test('asymmetric key ownership survives memory pressure', () async {
    for (var i = 0; i < 4; i++) {
      final alice = await EcdhPrivateKey.generateKey(EllipticCurve.p256);
      final bob = await EcdhPrivateKey.generateKey(EllipticCurve.p256);

      final aliceSecret = await alice.privateKey.deriveBits(256, bob.publicKey);
      final bobSecret = await bob.privateKey.deriveBits(256, alice.publicKey);
      expect(aliceSecret, equals(bobSecret));

      final privatePkcs8 = await alice.privateKey.exportPkcs8Key();
      final publicSpki = await alice.publicKey.exportSpkiKey();
      final importedPrivate = await EcdhPrivateKey.importPkcs8Key(
        privatePkcs8,
        EllipticCurve.p256,
      );
      final importedPublic = await EcdhPublicKey.importSpkiKey(
        publicSpki,
        EllipticCurve.p256,
      );
      expect(
        await importedPrivate.deriveBits(256, importedPublic),
        hasLength(32),
      );

      final privateJwk = await alice.privateKey.exportJsonWebKey();
      final publicJwk = await alice.publicKey.exportJsonWebKey();
      final importedPrivateJwk = await EcdhPrivateKey.importJsonWebKey(
        privateJwk,
        EllipticCurve.p256,
      );
      final importedPublicJwk = await EcdhPublicKey.importJsonWebKey(
        publicJwk,
        EllipticCurve.p256,
      );
      expect(
        await importedPrivateJwk.deriveBits(256, importedPublicJwk),
        hasLength(32),
      );

      await _applyMemoryPressure();
    }

    final rsa = await RsaOaepPrivateKey.generateKey(
      2048,
      BigInt.from(65537),
      Hash.sha256,
    );
    final privatePkcs8 = await rsa.privateKey.exportPkcs8Key();
    final publicSpki = await rsa.publicKey.exportSpkiKey();
    final privateKey = await RsaOaepPrivateKey.importPkcs8Key(
      privatePkcs8,
      Hash.sha256,
    );
    final publicKey = await RsaOaepPublicKey.importSpkiKey(
      publicSpki,
      Hash.sha256,
    );

    for (var i = 0; i < 3; i++) {
      final message = _bytes(32 + i, 500 + i);
      final label = _bytes(8, 600 + i);
      final ciphertext = await publicKey.encryptBytes(message, label: label);
      expect(await privateKey.decryptBytes(ciphertext, label: label), message);

      final privateJwk = await privateKey.exportJsonWebKey();
      final publicJwk = await publicKey.exportJsonWebKey();
      final privateJwkKey = await RsaOaepPrivateKey.importJsonWebKey(
        privateJwk,
        Hash.sha256,
      );
      final publicJwkKey = await RsaOaepPublicKey.importJsonWebKey(
        publicJwk,
        Hash.sha256,
      );
      final jwkCiphertext = await publicJwkKey.encryptBytes(
        message,
        label: label,
      );
      expect(
        await privateJwkKey.decryptBytes(jwkCiphertext, label: label),
        message,
      );

      await _applyMemoryPressure();
    }
  });

  test('failed imports leave later native operations usable', () async {
    final ecdh = await EcdhPrivateKey.generateKey(EllipticCurve.p256);
    final privatePkcs8 = await ecdh.privateKey.exportPkcs8Key();
    final publicSpki = await ecdh.publicKey.exportSpkiKey();

    await expectLater(
      EcdhPrivateKey.importPkcs8Key(
        _withCorruptedByte(privatePkcs8),
        EllipticCurve.p256,
      ),
      throwsFormatException,
    );
    await expectLater(
      EcdhPublicKey.importSpkiKey(
        _withCorruptedByte(publicSpki),
        EllipticCurve.p256,
      ),
      throwsFormatException,
    );

    await _applyMemoryPressure();

    final validPrivate = await EcdhPrivateKey.importPkcs8Key(
      privatePkcs8,
      EllipticCurve.p256,
    );
    final validPublic = await EcdhPublicKey.importSpkiKey(
      publicSpki,
      EllipticCurve.p256,
    );
    expect(await validPrivate.deriveBits(256, validPublic), hasLength(32));

    final rsa = await RsaOaepPrivateKey.generateKey(
      2048,
      BigInt.from(65537),
      Hash.sha256,
    );
    final rsaPrivatePkcs8 = await rsa.privateKey.exportPkcs8Key();
    final rsaPublicSpki = await rsa.publicKey.exportSpkiKey();

    await expectLater(
      RsaOaepPrivateKey.importPkcs8Key(
        _withCorruptedByte(rsaPrivatePkcs8),
        Hash.sha256,
      ),
      throwsFormatException,
    );
    await expectLater(
      RsaOaepPublicKey.importSpkiKey(
        _withCorruptedByte(rsaPublicSpki),
        Hash.sha256,
      ),
      throwsFormatException,
    );

    await _applyMemoryPressure();

    final validRsaPrivate = await RsaOaepPrivateKey.importPkcs8Key(
      rsaPrivatePkcs8,
      Hash.sha256,
    );
    final validRsaPublic = await RsaOaepPublicKey.importSpkiKey(
      rsaPublicSpki,
      Hash.sha256,
    );
    final message = _bytes(32, 700);
    final ciphertext = await validRsaPublic.encryptBytes(message);
    expect(await validRsaPrivate.decryptBytes(ciphertext), message);
  });
}

Uint8List _bytes(int length, int seed) {
  var state = seed & 0x7fffffff;
  final bytes = Uint8List(length);
  for (var i = 0; i < bytes.length; i++) {
    state = (state * 1103515245 + 12345) & 0x7fffffff;
    bytes[i] = state & 0xff;
  }
  return bytes;
}

Uint8List _withCorruptedByte(List<int> bytes) {
  final corrupted = Uint8List.fromList(bytes);
  corrupted[0] ^= 0xff;
  return corrupted;
}

Future<void> _applyMemoryPressure() async {
  final garbage = <Uint8List>[];
  var checksum = 0;
  for (var i = 0; i < 128; i++) {
    final block = Uint8List(4096);
    block[0] = i;
    checksum ^= block[0];
    garbage.add(block);
  }
  expect(garbage, hasLength(128));
  expect(checksum, isNonNegative);
  await Future<void>.delayed(Duration.zero);
}
