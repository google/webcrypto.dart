import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:webcrypto/webcrypto.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('public API RSA-OAEP supports all backend hashes', (_) async {
    final keyPair = await RsaOaepPrivateKey.generateKey(
      2048,
      BigInt.from(65537),
      Hash.sha256,
    );
    final pkcs8 = await keyPair.privateKey.exportPkcs8Key();
    final spki = await keyPair.publicKey.exportSpkiKey();
    final plaintext = utf8.encode('Android JCA RSA-OAEP');
    final label = utf8.encode('context');

    final imported = await RsaOaepPrivateKey.importPkcs8Key(pkcs8, Hash.sha256);
    final jwk = await imported.exportJsonWebKey();
    for (final name in ['n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qi']) {
      expect(jwk[name], isA<String>());
    }
    final fromJwk = await RsaOaepPrivateKey.importJsonWebKey(jwk, Hash.sha256);
    expect(await fromJwk.exportJsonWebKey(), jwk);
    final reimported = await RsaOaepPrivateKey.importPkcs8Key(
      await fromJwk.exportPkcs8Key(),
      Hash.sha256,
    );
    expect(await reimported.exportJsonWebKey(), jwk);
    final jwkCiphertext = await keyPair.publicKey.encryptBytes(plaintext);
    expect(await fromJwk.decryptBytes(jwkCiphertext), plaintext);

    final malformed = Uint8List.fromList(pkcs8);
    malformed[malformed.length - 1] ^= 1;
    await expectLater(
      RsaOaepPrivateKey.importPkcs8Key(malformed, Hash.sha256),
      throwsA(isA<FormatException>()),
    );

    for (final hash in <Hash>[
      Hash.sha1,
      Hash.sha256,
      Hash.sha384,
      Hash.sha512,
    ]) {
      final privateKey = await RsaOaepPrivateKey.importPkcs8Key(pkcs8, hash);
      final publicKey = await RsaOaepPublicKey.importSpkiKey(spki, hash);
      final ciphertext = await publicKey.encryptBytes(plaintext, label: label);

      expect(
        await privateKey.decryptBytes(ciphertext, label: label),
        plaintext,
      );
      await expectLater(
        privateKey.decryptBytes(ciphertext, label: utf8.encode('wrong')),
        throwsA(isA<OperationError>()),
      );
    }
  });
}
