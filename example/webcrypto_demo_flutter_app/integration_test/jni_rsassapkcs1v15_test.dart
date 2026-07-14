import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:webcrypto/webcrypto.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('public API RSASSA-PKCS1-v1_5 signs and verifies', (_) async {
    final keyPair = await RsassaPkcs1V15PrivateKey.generateKey(
      2048,
      BigInt.from(65537),
      Hash.sha256,
    );
    final privateKey = await RsassaPkcs1V15PrivateKey.importJsonWebKey(
      await keyPair.privateKey.exportJsonWebKey(),
      Hash.sha256,
    );
    final publicKey = await RsassaPkcs1V15PublicKey.importJsonWebKey(
      await keyPair.publicKey.exportJsonWebKey(),
      Hash.sha256,
    );
    final data = utf8.encode('Android JCA RSASSA-PKCS1-v1_5');
    final signature = await privateKey.signBytes(data);

    expect(await publicKey.verifyBytes(signature, data), isTrue);

    final modified = Uint8List.fromList(data)..[0] ^= 0x01;
    expect(await publicKey.verifyBytes(signature, modified), isFalse);
  });
}
