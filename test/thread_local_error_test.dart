@TestOn('vm')
library thread_local_error_test;

import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webcrypto/webcrypto.dart';

// This relies on internal implementation details to check for error leaks.
// If implementation changes significantly, this test might need updates.
import 'package:webcrypto/src/boringssl/lookup/lookup.dart'; // Access internal ssl

void main() {
  test('BoringSSL error stack is empty after operations', () async {
    // Helper to check error stack
    void checkErrorStack() {
      // We peep at the error stack to see if anything was left behind.
      // Operations must clean up after themselves.
      final err = ssl.ERR_peek_error();
      if (err != 0) {
        // Just failing with the error code is sufficient to signal a leak.
        fail('BoringSSL error stack not empty. Error code: $err');
      }
    }

    // Initial check to ensure clean slate
    checkErrorStack();

    // 1. Digest (SHA-256)
    await Hash.sha256.digestBytes(Uint8List(10));
    checkErrorStack();

    // 2. HMAC Generation & Sign & Verify
    final hmacKey = await HmacSecretKey.generateKey(Hash.sha256);
    checkErrorStack();
    final signature = await hmacKey.signBytes(Uint8List(10));
    checkErrorStack();
    final isValid = await hmacKey.verifyBytes(signature, Uint8List(10));
    expect(isValid, isTrue);
    checkErrorStack();

    // 3. HMAC Verify Failure
    // Flip a bit in signature to cause verification failure
    final invalidSig = Uint8List.fromList(signature);
    if (invalidSig.isNotEmpty) {
      invalidSig[0] ^= 0xff;
    }
    final isInvalid = await hmacKey.verifyBytes(invalidSig, Uint8List(10));
    expect(isInvalid, isFalse);
    checkErrorStack();
    
    // 4. AES-GCM
    final aesKey = await AesGcmSecretKey.generateKey(256);
    checkErrorStack();
    final iv = Uint8List(12);
    final encrypted = await aesKey.encryptBytes(Uint8List(10), iv);
    checkErrorStack();
    await aesKey.decryptBytes(encrypted, iv);
    checkErrorStack();
    
    // 5. ECDSA
    final ecKey = await EcdsaPrivateKey.generateKey(EllipticCurve.p256);
    checkErrorStack();
    final ecSig = await ecKey.privateKey.signBytes(Uint8List(10), Hash.sha256);
    checkErrorStack();
    final ecValid = await ecKey.publicKey.verifyBytes(ecSig, Uint8List(10), Hash.sha256);
    expect(ecValid, isTrue);
    checkErrorStack();

    // 6. Randomness
    final randomBytes = Uint8List(32);
    fillRandomBytes(randomBytes);
    checkErrorStack();

    // 7. Expected Failure (Import invalid JWK)
    try {
      // Missing 'k' property or invalid format
      await AesGcmSecretKey.importJsonWebKey({'kty': 'oct', 'alg': 'A256GCM'});
      fail('Should have thrown ArgumentError or FormatException');
    } catch (_) {
      // Expected exception
      checkErrorStack();
    }
  });
}
