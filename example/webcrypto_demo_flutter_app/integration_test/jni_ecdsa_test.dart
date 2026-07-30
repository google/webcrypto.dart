import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:webcrypto/webcrypto.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('public API ECDSA supports every named curve', (_) async {
    for (final testCase
        in <({EllipticCurve curve, Hash hash, int signatureLength})>[
          (curve: EllipticCurve.p256, hash: Hash.sha256, signatureLength: 64),
          (curve: EllipticCurve.p384, hash: Hash.sha384, signatureLength: 96),
          (curve: EllipticCurve.p521, hash: Hash.sha512, signatureLength: 132),
        ]) {
      final keyPair = await EcdsaPrivateKey.generateKey(testCase.curve);
      final pkcs8PrivateKey = await EcdsaPrivateKey.importPkcs8Key(
        await keyPair.privateKey.exportPkcs8Key(),
        testCase.curve,
      );
      final spkiPublicKey = await EcdsaPublicKey.importSpkiKey(
        await keyPair.publicKey.exportSpkiKey(),
        testCase.curve,
      );
      final privateKey = await EcdsaPrivateKey.importJsonWebKey(
        await pkcs8PrivateKey.exportJsonWebKey(),
        testCase.curve,
      );
      final publicKey = await EcdsaPublicKey.importRawKey(
        await spkiPublicKey.exportRawKey(),
        testCase.curve,
      );
      final data = utf8.encode('Android JCA ECDSA ${testCase.curve.name}');
      final signature = await privateKey.signBytes(data, testCase.hash);

      expect(signature, hasLength(testCase.signatureLength));
      expect(
        await publicKey.verifyBytes(signature, data, testCase.hash),
        isTrue,
      );
    }
  });
}
