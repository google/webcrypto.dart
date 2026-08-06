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

  testWidgets('public API imports point-less PKCS#8 for every curve', (
    _,
  ) async {
    for (final testCase
        in <
          ({
            EllipticCurve curve,
            Hash hash,
            String pkcs8,
            String x,
            String y,
            int coordinateLength,
          })
        >[
          (
            curve: EllipticCurve.p256,
            hash: Hash.sha256,
            pkcs8:
                'MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCAZRfVHkag02wh9ytAbU7f0bm4YI4zQWc91TuwpP5TQew==',
            x: 'tX4HmKqZlUvwKvjuHNIM9OvhRI_Zl-NNle1fWfCbScc',
            y: 'EJm8vj7qHds9LDOLDxStXZiDkxHmP6lVu15SIEE9ifo',
            coordinateLength: 32,
          ),
          (
            curve: EllipticCurve.p384,
            hash: Hash.sha384,
            pkcs8:
                'ME4CAQAwEAYHKoZIzj0CAQYFK4EEACIENzA1AgEBBDBfOl8Xqbd/1o5/+b52/TlXU0Q20ZErxTDDU8I+n0uogkALP0uJdqppnLkmAxxbHio=',
            x: '4O6K98EelmMlJagNn4r7kTScb_fBDnUsicijL2voYEYFz0Dyxi-7WX8hwLnTvmIi',
            y: 'O2FwYF-W_jwTO0Sf1Og6XIMT_bzsCWbqmhbt8Sc2VSXaZp0O7RIG87cHDzUU7b8M',
            coordinateLength: 48,
          ),
          (
            curve: EllipticCurve.p521,
            hash: Hash.sha512,
            pkcs8:
                'MGACAQAwEAYHKoZIzj0CAQYFK4EEACMESTBHAgEBBEIACuKKo5naCwYJhwpDO1snqNqtByW+0/oydzi5R+M2NcZ2nNeSV0MnjxsougqkvnC9bbXPuXJMKyIJKX71XXII3JI=',
            x: 'AKmqGSgUO4HKPW6_0kVHmGYxb5jRhWtzvNyRww2Hg10Yc_U1QE5tOJXikFpDsaeXppgMjQ6PZTOu0yB_RYaz_ll_',
            y: 'AIQZuuh63cVeKKY6rPoS9ZoKs80ROOtt8YBKYd61A_rWJlfHEeyP9B4-LbXhv8u0cccAC5H00TDsxc6DrNnP3UJT',
            coordinateLength: 66,
          ),
        ]) {
      final privateKey = await EcdsaPrivateKey.importPkcs8Key(
        base64.decode(testCase.pkcs8),
        testCase.curve,
      );
      final privateJwk = await privateKey.exportJsonWebKey();
      expect(privateJwk['x'], testCase.x);
      expect(privateJwk['y'], testCase.y);
      expect(
        base64Url.decode(base64Url.normalize(privateJwk['x'] as String)),
        hasLength(testCase.coordinateLength),
      );
      expect(
        base64Url.decode(base64Url.normalize(privateJwk['y'] as String)),
        hasLength(testCase.coordinateLength),
      );

      final publicJwk = Map<String, dynamic>.of(privateJwk)..remove('d');
      final publicKey = await EcdsaPublicKey.importJsonWebKey(
        publicJwk,
        testCase.curve,
      );
      final data = utf8.encode('point-less PKCS#8 ${testCase.curve.name}');
      final signature = await privateKey.signBytes(data, testCase.hash);
      expect(
        await publicKey.verifyBytes(signature, data, testCase.hash),
        isTrue,
      );
    }
  });
}
