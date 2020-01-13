@TestOn('!firefox')
library ecdsa_test;

import 'package:webcrypto/webcrypto.dart';
import '../utils.dart';
import '../testrunner.dart';
import 'package:test/test.dart';

final runner = TestRunner<EcdsaPrivateKey, EcdsaPublicKey>(
  importPrivateRawKey: null, // not supported
  exportPrivateRawKey: null,
  importPrivatePkcs8Key: (keyData, keyImportParams) =>
      EcdsaPrivateKey.importPkcs8Key(keyData, curveFromJson(keyImportParams)),
  exportPrivatePkcs8Key: (key) => key.exportPkcs8Key(),
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

  return;
  runner.runAll([
    {
      "name": "test key generation",
      "generateKeyParams": {"curve": "p-256"},
      "plaintext":
          "dXNjaXBpdCBhdCB2ZWhpY3VsYQppZCwgdmVzdGlidWx1bSBuZWMgbmlzbC4gRHVpcyBlcmF0IG5pc2ksIHJob25jdQ==",
      "importKeyParams": {"curve": "p-256"},
      "signVerifyParams": {"hash": "sha-256"}
    },
    {
      "name":
          "spki publicKey generated on ffi/boringssl at 2020-01-03T21:03:10",
      "privatePkcs8KeyData":
          "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgrU1WG6Hs6NaqEE/qe0dwA6QEsu7Ni/d96CbC9BCpqKihRANCAARNHP9zOrwjz/8+U9AUsP8dxhMF1DZsrbCdsV8F12BzNaSPVexQOSuJyZCPJ1L/QQok4B/nfJXP67WPTq8iccB9",
      "publicSpkiKeyData":
          "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETRz/czq8I8//PlPQFLD/HcYTBdQ2bK2wnbFfBddgczWkj1XsUDkricmQjydS/0EKJOAf53yVz+u1j06vInHAfQ==",
      "plaintext":
          "dXNjaXBpdCBhdCB2ZWhpY3VsYQppZCwgdmVzdGlidWx1bSBuZWMgbmlzbC4gRHVpcyBlcmF0IG5pc2ksIHJob25jdQ==",
      "signature":
          "REL42ut53YTaCq2yJpczHUM9vlncEl/UUXhl55zXuHyhgbIuGg0ORoiDb9wyxXVMcWVmPu6rlRculwVUS/+zag==",
      "importKeyParams": {"curve": "p-256"},
      "signVerifyParams": {"hash": "sha-256"}
    },
    {
      "name": "raw publicKey generated on ffi/boringssl at 2020-01-03T21:03:10",
      "privatePkcs8KeyData":
          "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgrU1WG6Hs6NaqEE/qe0dwA6QEsu7Ni/d96CbC9BCpqKihRANCAARNHP9zOrwjz/8+U9AUsP8dxhMF1DZsrbCdsV8F12BzNaSPVexQOSuJyZCPJ1L/QQok4B/nfJXP67WPTq8iccB9",
      "publicRawKeyData":
          "BE0c/3M6vCPP/z5T0BSw/x3GEwXUNmytsJ2xXwXXYHM1pI9V7FA5K4nJkI8nUv9BCiTgH+d8lc/rtY9OryJxwH0=",
      "plaintext":
          "dXNjaXBpdCBhdCB2ZWhpY3VsYQppZCwgdmVzdGlidWx1bSBuZWMgbmlzbC4gRHVpcyBlcmF0IG5pc2ksIHJob25jdQ==",
      "signature":
          "REL42ut53YTaCq2yJpczHUM9vlncEl/UUXhl55zXuHyhgbIuGg0ORoiDb9wyxXVMcWVmPu6rlRculwVUS/+zag==",
      "importKeyParams": {"curve": "p-256"},
      "signVerifyParams": {"hash": "sha-256"}
    },
    {
      "name": "spki publicKey generated on chrome/linux at 2020-01-03T22:05:31",
      "privatePkcs8KeyData":
          "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg/WauL7/X/mF+AkZDklWiCnHP8oMyzOOAx3zP2JRAZqShRANCAAQz8olCz21PXbgAiXkhD/GOHEH1/df6zu8mengd3LqaT1C1NBgHjVk7gkv96Q+JVK4yIBdaCxHMiJ44nxfUrzbv",
      "publicSpkiKeyData":
          "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEM/KJQs9tT124AIl5IQ/xjhxB9f3X+s7vJnp4Hdy6mk9QtTQYB41ZO4JL/ekPiVSuMiAXWgsRzIieOJ8X1K827w==",
      "plaintext": "IGNvbnNlY3RldHU=",
      "signature":
          "unsIQHmaKdXcTiSb2v++xqbJvn4orC5/6OmKd5HzR7phqMBZ656iGgTH+atHdDY4zu2nPk4wV2rPh3biTlUHlw==",
      "importKeyParams": {"curve": "p-256"},
      "signVerifyParams": {"hash": "sha-256"}
    },
    {
      "name": "raw publicKey generated on chrome/linux at 2020-01-03T22:05:31",
      "privatePkcs8KeyData":
          "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg/WauL7/X/mF+AkZDklWiCnHP8oMyzOOAx3zP2JRAZqShRANCAAQz8olCz21PXbgAiXkhD/GOHEH1/df6zu8mengd3LqaT1C1NBgHjVk7gkv96Q+JVK4yIBdaCxHMiJ44nxfUrzbv",
      "publicRawKeyData":
          "BDPyiULPbU9duACJeSEP8Y4cQfX91/rO7yZ6eB3cuppPULU0GAeNWTuCS/3pD4lUrjIgF1oLEcyInjifF9SvNu8=",
      "plaintext": "IGNvbnNlY3RldHU=",
      "signature":
          "unsIQHmaKdXcTiSb2v++xqbJvn4orC5/6OmKd5HzR7phqMBZ656iGgTH+atHdDY4zu2nPk4wV2rPh3biTlUHlw==",
      "importKeyParams": {"curve": "p-256"},
      "signVerifyParams": {"hash": "sha-256"}
    },
    // TODO: generate on firefox, once the import/export pkcs8 has been figured out
  ]);
}
