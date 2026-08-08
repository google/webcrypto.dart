import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:webcrypto/webcrypto.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('public API ECDH supports every named curve', (_) async {
    for (final testCase in <({EllipticCurve curve, int maxLength})>[
      (curve: EllipticCurve.p256, maxLength: 256),
      (curve: EllipticCurve.p384, maxLength: 384),
      (curve: EllipticCurve.p521, maxLength: 528),
    ]) {
      final alice = await EcdhPrivateKey.generateKey(testCase.curve);
      final bob = await EcdhPrivateKey.generateKey(testCase.curve);
      final privateKey = await EcdhPrivateKey.importPkcs8Key(
        await alice.privateKey.exportPkcs8Key(),
        testCase.curve,
      );
      final publicKey = await EcdhPublicKey.importRawKey(
        await bob.publicKey.exportRawKey(),
        testCase.curve,
      );

      final derived = await privateKey.deriveBits(
        testCase.maxLength,
        publicKey,
      );
      final reciprocal = await bob.privateKey.deriveBits(
        testCase.maxLength,
        alice.publicKey,
      );
      expect(derived, hasLength(testCase.maxLength ~/ 8));
      expect(derived, reciprocal);

      final partialLength = testCase.maxLength - 1;
      final partial = await privateKey.deriveBits(partialLength, publicKey);
      expect(partial, hasLength((partialLength + 7) ~/ 8));
      expect(partial.last & 1, 0);
    }
  });

  testWidgets('public API ECDH JWK metadata is interoperable', (_) async {
    final keyPair = await EcdhPrivateKey.generateKey(EllipticCurve.p521);
    final privateJwk = await keyPair.privateKey.exportJsonWebKey();
    final publicJwk = await keyPair.publicKey.exportJsonWebKey();

    expect(privateJwk, isNot(contains('use')));
    expect(publicJwk, isNot(contains('use')));
    expect(
      base64Url.decode(base64Url.normalize(privateJwk['x'] as String)),
      hasLength(66),
    );
    expect(
      base64Url.decode(base64Url.normalize(privateJwk['y'] as String)),
      hasLength(66),
    );

    final importedPrivateKey = await EcdhPrivateKey.importJsonWebKey(
      Map<String, dynamic>.of(privateJwk)
        ..['use'] = 'enc'
        ..['alg'] = 'custom-ecdh-algorithm',
      EllipticCurve.p521,
    );
    final importedPublicKey = await EcdhPublicKey.importJsonWebKey(
      Map<String, dynamic>.of(publicJwk)..['use'] = 'enc',
      EllipticCurve.p521,
    );
    expect(
      await importedPrivateKey.deriveBits(528, importedPublicKey),
      await keyPair.privateKey.deriveBits(528, keyPair.publicKey),
    );
  });
}
