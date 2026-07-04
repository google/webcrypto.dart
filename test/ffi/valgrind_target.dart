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

import 'dart:async';
import 'dart:typed_data';

import 'package:webcrypto/webcrypto.dart';

Future<void> main() async {
  await _exerciseSymmetricOperations();
  await _exerciseAsymmetricKeyOwnership();
  await _exerciseCleanupAfterFailedImports();
  // ignore: avoid_print
  print('Cryptographic operations survived memory pressure.');
}

Future<void> _exerciseSymmetricOperations() async {
  for (var i = 0; i < 16; i++) {
    final message = _bytes(64 + i, i);
    final digest = await Hash.sha256.digestBytes(message);
    _expectLength(digest, 32, 'SHA-256 digest');

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
    _expectBytes(plaintext, message, 'AES-GCM plaintext');
    _expectBytes(await aesKey.exportRawKey(), aesKeyData, 'AES-GCM raw key');

    final aesJwk = await aesKey.exportJsonWebKey();
    final aesJwkKey = await AesGcmSecretKey.importJsonWebKey(aesJwk);
    _expectBytes(await aesJwkKey.exportRawKey(), aesKeyData, 'AES-GCM JWK key');

    final hmacKeyData = _bytes(32, 400 + i);
    final hmacKey = await HmacSecretKey.importRawKey(hmacKeyData, Hash.sha256);
    final signature = await hmacKey.signBytes(message);
    _check(
      await hmacKey.verifyBytes(signature, message),
      'HMAC signature verification failed.',
    );
    _expectBytes(await hmacKey.exportRawKey(), hmacKeyData, 'HMAC raw key');

    final hmacJwk = await hmacKey.exportJsonWebKey();
    final hmacJwkKey = await HmacSecretKey.importJsonWebKey(
      hmacJwk,
      Hash.sha256,
    );
    _check(
      await hmacJwkKey.verifyBytes(signature, message),
      'HMAC JWK signature verification failed.',
    );

    if (i.isEven) {
      await _applyMemoryPressure();
    }
  }
}

Future<void> _exerciseAsymmetricKeyOwnership() async {
  for (var i = 0; i < 4; i++) {
    final alice = await EcdhPrivateKey.generateKey(EllipticCurve.p256);
    final bob = await EcdhPrivateKey.generateKey(EllipticCurve.p256);

    final aliceSecret = await alice.privateKey.deriveBits(256, bob.publicKey);
    final bobSecret = await bob.privateKey.deriveBits(256, alice.publicKey);
    _expectBytes(aliceSecret, bobSecret, 'ECDH shared secret');

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
    _expectLength(
      await importedPrivate.deriveBits(256, importedPublic),
      32,
      'Imported ECDH shared secret',
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
    _expectLength(
      await importedPrivateJwk.deriveBits(256, importedPublicJwk),
      32,
      'Imported ECDH JWK shared secret',
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
    _expectBytes(
      await privateKey.decryptBytes(ciphertext, label: label),
      message,
      'RSA-OAEP plaintext',
    );

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
    _expectBytes(
      await privateJwkKey.decryptBytes(jwkCiphertext, label: label),
      message,
      'RSA-OAEP JWK plaintext',
    );

    await _applyMemoryPressure();
  }
}

Future<void> _exerciseCleanupAfterFailedImports() async {
  final ecdh = await EcdhPrivateKey.generateKey(EllipticCurve.p256);
  final privatePkcs8 = await ecdh.privateKey.exportPkcs8Key();
  final publicSpki = await ecdh.publicKey.exportSpkiKey();

  await _expectFormatException(
    EcdhPrivateKey.importPkcs8Key(
      _withCorruptedByte(privatePkcs8),
      EllipticCurve.p256,
    ),
    'corrupt ECDH PKCS8 import',
  );
  await _expectFormatException(
    EcdhPublicKey.importSpkiKey(
      _withCorruptedByte(publicSpki),
      EllipticCurve.p256,
    ),
    'corrupt ECDH SPKI import',
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
  _expectLength(
    await validPrivate.deriveBits(256, validPublic),
    32,
    'Valid ECDH operation after failed imports',
  );

  final rsa = await RsaOaepPrivateKey.generateKey(
    2048,
    BigInt.from(65537),
    Hash.sha256,
  );
  final rsaPrivatePkcs8 = await rsa.privateKey.exportPkcs8Key();
  final rsaPublicSpki = await rsa.publicKey.exportSpkiKey();

  await _expectFormatException(
    RsaOaepPrivateKey.importPkcs8Key(
      _withCorruptedByte(rsaPrivatePkcs8),
      Hash.sha256,
    ),
    'corrupt RSA PKCS8 import',
  );
  await _expectFormatException(
    RsaOaepPublicKey.importSpkiKey(
      _withCorruptedByte(rsaPublicSpki),
      Hash.sha256,
    ),
    'corrupt RSA SPKI import',
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
  _expectBytes(
    await validRsaPrivate.decryptBytes(ciphertext),
    message,
    'Valid RSA operation after failed imports',
  );
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

Future<void> _expectFormatException(
  Future<Object?> operation,
  String description,
) async {
  try {
    await operation;
  } on FormatException {
    return;
  }
  throw StateError('$description did not throw FormatException.');
}

void _expectBytes(List<int> actual, List<int> expected, String description) {
  if (actual.length != expected.length) {
    throw StateError(
      '$description had length ${actual.length}; expected ${expected.length}.',
    );
  }
  for (var i = 0; i < actual.length; i++) {
    if (actual[i] != expected[i]) {
      throw StateError('$description differed at byte $i.');
    }
  }
}

void _expectLength(List<int> value, int length, String description) {
  if (value.length != length) {
    throw StateError(
      '$description had length ${value.length}; expected $length.',
    );
  }
}

void _check(bool condition, String message) {
  if (!condition) {
    throw StateError(message);
  }
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
  _check(garbage.length == 128, 'Memory-pressure allocation was incomplete.');
  _check(checksum >= 0, 'Memory-pressure checksum was invalid.');
  await Future<void>.delayed(Duration.zero);
}
