import 'package:webcrypto/webcrypto.dart';
import '../utils.dart';
import '../testrunner.dart';

// HACK: This test file is only present, because Firefox doesn't support pkcs8
//       so we have to skip Firefox in ecdsa_test.dart
import 'ecdsa_test.dart' show testCases;

final runner = TestRunner<EcdsaPrivateKey, EcdsaPublicKey>(
  importPrivateRawKey: null, // not supported
  exportPrivateRawKey: null,
  // Not supported on Firefox
  //importPrivatePkcs8Key: (keyData, keyImportParams) =>
  //    EcdsaPrivateKey.importPkcs8Key(keyData, curveFromJson(keyImportParams)),
  //exportPrivatePkcs8Key: (key) => key.exportPkcs8Key(),
  importPrivateJsonWebKey: (jsonWebKeyData, keyImportParams) =>
      EcdsaPrivateKey.importJsonWebKey(
          jsonWebKeyData, curveFromJson(keyImportParams)),
  exportPrivateJsonWebKey: (key) => key.exportJsonWebKey(),
  importPublicRawKey: (keyData, keyImportParams) =>
      EcdsaPublicKey.importRawKey(keyData, curveFromJson(keyImportParams)),
  exportPublicRawKey: (key) => key.exportRawKey(),
  importPublicSpkiKey: (keyData, keyImportParams) =>
      EcdsaPublicKey.importSpkiKey(keyData, curveFromJson(keyImportParams)),
  exportPublicSpkiKey: (key) => key.exportSpkiKey(),
  importPublicJsonWebKey: (jsonWebKeyData, keyImportParams) =>
      EcdsaPublicKey.importJsonWebKey(
          jsonWebKeyData, curveFromJson(keyImportParams)),
  exportPublicJsonWebKey: (key) => key.exportJsonWebKey(),
  generateKeyPair: (generateKeyPairParams) => EcdsaPrivateKey.generateKey(
    curveFromJson(generateKeyPairParams),
  ),
  signBytes: (key, data, signParams) =>
      key.signBytes(data, hashFromJson(signParams)),
  signStream: (key, data, signParams) =>
      key.signStream(data, hashFromJson(signParams)),
  verifyBytes: (key, signature, data, verifyParams) =>
      key.verifyBytes(signature, data, hashFromJson(verifyParams)),
  verifyStream: (key, signature, data, verifyParams) =>
      key.verifyStream(signature, data, hashFromJson(verifyParams)),
);

void main() {
  test('generate ECDSA test case', () async {
    await runner.generate(
      generateKeyParams: {'curve': curveToJson(EllipticCurve.p256)},
      importKeyParams: {'curve': curveToJson(EllipticCurve.p256)},
      signVerifyParams: {'hash': hashToJson(Hash.sha256)},
      maxPlaintext: 80,
    );
  });

  // TODO: Test more curves and hashes
  runner.runAll(testCases.map((c) => Map.fromEntries(c.entries.where(
        (e) => e.key != 'privatePkcs8KeyData',
      ))));
}
