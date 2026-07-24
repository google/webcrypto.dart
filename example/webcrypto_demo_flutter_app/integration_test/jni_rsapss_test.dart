import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:webcrypto/webcrypto.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('public API RSA-PSS supports all backend hashes', (_) async {
    final keyPair = await RsaPssPrivateKey.generateKey(
      2048,
      BigInt.from(65537),
      Hash.sha256,
    );
    final pkcs8 = await keyPair.privateKey.exportPkcs8Key();
    final spki = await keyPair.publicKey.exportSpkiKey();
    final data = utf8.encode('Android JCA RSA-PSS');
    final modified = Uint8List.fromList(data)..[0] ^= 0x01;

    for (final (hash, saltLength) in <(Hash, int)>[
      (Hash.sha1, 20),
      (Hash.sha256, 32),
      (Hash.sha384, 48),
      (Hash.sha512, 64),
    ]) {
      final privateKey = await RsaPssPrivateKey.importPkcs8Key(pkcs8, hash);
      final publicKey = await RsaPssPublicKey.importSpkiKey(spki, hash);
      final signature = await privateKey.signBytes(data, saltLength);

      expect(await publicKey.verifyBytes(signature, data, saltLength), isTrue);
      expect(
        await publicKey.verifyBytes(signature, modified, saltLength),
        isFalse,
      );
    }
  });
}
