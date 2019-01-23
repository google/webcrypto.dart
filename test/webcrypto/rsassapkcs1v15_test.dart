@TestOn('browser')

import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webcrypto/webcrypto.dart';

Stream<List<int>> asStream(String data) async* {
  yield Uint8List.fromList(utf8.encode(data));
}

const _sampleMessage = 'Good morning is an important message!';

void main() {
  // Shared state
  RsassaPkcs1V15PrivateKey privateKey;
  RsassaPkcs1V15PublicKey publicKey;
  List<int> sig;

  test('generateKey', () async {
    final pair = await RsassaPkcs1V15PrivateKey.generateKey(
      modulusLength: 2048,
      publicExponent: BigInt.from(65537),
      hash: HashAlgorithm.sha256,
      extractable: true,
      usages: [
        KeyUsage.sign,
        KeyUsage.verify,
      ],
    );
    privateKey = pair.privateKey;
    publicKey = pair.publicKey;
    expect(privateKey, isNotNull);
    expect(publicKey, isNotNull);
    expect(privateKey.extractable, isTrue);
    expect(publicKey.extractable, isTrue);
  });

  test('sign', () async {
    sig = await privateKey.sign(
      data: asStream(_sampleMessage),
    );
    expect(sig, isNotNull);
  });

  test('verify (positive)', () async {
    final result = await publicKey.verify(
      signature: sig,
      data: asStream(_sampleMessage),
    );
    expect(result, isTrue);
  });

  test('verify (negative 1)', () async {
    final result = await publicKey.verify(
      signature: sig,
      data: asStream(_sampleMessage + ' hijacted message'),
    );
    expect(result, isFalse);
  });

  test('verify (negative 2)', () async {
    final sig2 = List<int>.from(sig);
    // Modify the signature by setting the first 8 bytes to 42
    for (int i = 0; i < 8; i++) {
      sig2[i] = 42;
    }
    final result = await publicKey.verify(
      signature: sig2,
      data: asStream(_sampleMessage),
    );
    expect(result, isFalse);
  });

  test('export/import (private)', () async {
    final keyData = await privateKey.exportPkcs8Key();
    final key = await RsassaPkcs1V15PrivateKey.importPkcs8Key(
      keyData: keyData,
      hash: HashAlgorithm.sha256,
      extractable: true,
      usages: [KeyUsage.sign],
    );
    // Compare two exports of the key
    final keyData2 = await key.exportPkcs8Key();
    expect(base64.encode(keyData2), equals(base64.encode(keyData2)));

    // Test verify
    final sig2 = await key.sign(data: asStream(_sampleMessage));
    final result = await publicKey.verify(
      signature: sig2,
      data: asStream(_sampleMessage),
    );
    expect(result, isTrue);
  });

  test('export/import (public)', () async {
    final keyData = await publicKey.exportSpkiKey();
    final key = await RsassaPkcs1V15PublicKey.importSpkiKey(
      keyData: keyData,
      hash: HashAlgorithm.sha256,
      extractable: true,
      usages: [KeyUsage.verify],
    );
    // Compare two exports of the key
    final keyData2 = await key.exportSpkiKey();
    expect(base64.encode(keyData2), equals(base64.encode(keyData2)));

    // Test verify
    final result = await publicKey.verify(
      signature: sig,
      data: asStream(_sampleMessage),
    );
    expect(result, isTrue);
  });

  test('extractable (public)', () async {
    final keyData = await privateKey.exportPkcs8Key();
    final key = await RsassaPkcs1V15PrivateKey.importPkcs8Key(
      keyData: keyData,
      hash: HashAlgorithm.sha256,
      extractable: false,
      usages: [KeyUsage.sign],
    );
    // Test that we can't extract
    await expectLater(key.exportPkcs8Key(), throwsStateError);
  });

  test('extractable (public)', () async {
    final keyData = await publicKey.exportSpkiKey();
    final key = await RsassaPkcs1V15PublicKey.importSpkiKey(
      keyData: keyData,
      hash: HashAlgorithm.sha256,
      extractable: false,
      usages: [KeyUsage.verify],
    );
    // Test that we can't extract
    await expectLater(key.exportSpkiKey(), throwsStateError);
  });
}
