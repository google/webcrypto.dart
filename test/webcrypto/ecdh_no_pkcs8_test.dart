library ecdh_no_pkcs8_test;

import 'package:webcrypto/webcrypto.dart';
import '../utils.dart';
import '../testrunner.dart';

// HACK: This test file is only present, because Firefox doesn't support pkcs8
//       so we have to skip Firefox in ecdh_test.dart
import 'ecdh_test.dart' show testCases;

class _KeyPair<S, T> implements KeyPair<S, T> {
  final S privateKey;
  final T publicKey;
  _KeyPair({this.privateKey, this.publicKey});
}

final runner = TestRunner.asymmetric<EcdhPrivateKey, EcdhPublicKey>(
  importPrivateRawKey: null, // not supported
  exportPrivateRawKey: null,
  // Not supported on Firefox
  // importPrivatePkcs8Key: (keyData, keyImportParams) =>
  //     EcdhPrivateKey.importPkcs8Key(keyData, curveFromJson(keyImportParams)),
  // exportPrivatePkcs8Key: (key) => key.exportPkcs8Key(),
  importPrivateJsonWebKey: (jsonWebKeyData, keyImportParams) =>
      EcdhPrivateKey.importJsonWebKey(
          jsonWebKeyData, curveFromJson(keyImportParams)),
  exportPrivateJsonWebKey: (key) => key.exportJsonWebKey(),
  importPublicRawKey: (keyData, keyImportParams) =>
      EcdhPublicKey.importRawKey(keyData, curveFromJson(keyImportParams)),
  exportPublicRawKey: (key) => key.exportRawKey(),
  importPublicSpkiKey: (keyData, keyImportParams) =>
      EcdhPublicKey.importSpkiKey(keyData, curveFromJson(keyImportParams)),
  exportPublicSpkiKey: (key) => key.exportSpkiKey(),
  importPublicJsonWebKey: (jsonWebKeyData, keyImportParams) =>
      EcdhPublicKey.importJsonWebKey(
          jsonWebKeyData, curveFromJson(keyImportParams)),
  exportPublicJsonWebKey: (key) => key.exportJsonWebKey(),
  generateKeyPair: (generateKeyPairParams) async {
    // Use public / private keys from two different pairs, as if they had been
    // exchanged.
    final a = await EcdhPrivateKey.generateKey(curveFromJson(
      generateKeyPairParams,
    ));
    final b = await EcdhPrivateKey.generateKey(curveFromJson(
      generateKeyPairParams,
    ));
    return _KeyPair(
      privateKey: a.privateKey,
      publicKey: b.publicKey,
    );
  },
  deriveBits: (keys, length, deriveParams) => keys.privateKey.deriveBits(
    length,
    keys.publicKey,
  ),
);

void main() {
  test('generate ECDH test case', () async {
    await runner.generate(
      generateKeyParams: {'curve': curveToJson(EllipticCurve.p521)},
      importKeyParams: {'curve': curveToJson(EllipticCurve.p521)},
      deriveParams: {},
      maxDeriveLength: 528,
    );
  });

  runner.runAll(testCases.map((c) => Map.fromEntries(c.entries.where(
        (e) => e.key != 'privatePkcs8KeyData',
      ))));
}
