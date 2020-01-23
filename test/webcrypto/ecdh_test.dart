@TestOn('!firefox') // Firefox doesn't support pkcs8 import/export for ECDSA.
library ecdh_test;

import 'package:webcrypto/webcrypto.dart';
import '../utils.dart';
import '../testrunner.dart';
import 'package:test/test.dart' show TestOn;

class _KeyPair<S, T> implements KeyPair<S, T> {
  final S privateKey;
  final T publicKey;
  _KeyPair({this.privateKey, this.publicKey});
}

final runner = TestRunner.asymmetric<EcdhPrivateKey, EcdhPublicKey>(
  importPrivateRawKey: null, // not supported
  exportPrivateRawKey: null,
  importPrivatePkcs8Key: (keyData, keyImportParams) =>
      EcdhPrivateKey.importPkcs8Key(keyData, curveFromJson(keyImportParams)),
  exportPrivatePkcs8Key: (key) => key.exportPkcs8Key(),
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
      generateKeyParams: {'curve': curveToJson(EllipticCurve.p256)},
      importKeyParams: {'curve': curveToJson(EllipticCurve.p256)},
      deriveParams: {},
      maxDeriveLength: 27,
    );
  });

  // TODO: Test more curves and hashes
  runner.runAll(testCases);
}

// Exported for use in ecdh_no_pkcs8_test.dart
final testCases = [
  {
    "name": "generated at 2020-01-22T23:24:34",
    "privatePkcs8KeyData":
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg3aTiZ7odKAODYk4BpZlzulBCB/BptmxjtvrzyXI71UyhRANCAATl0GVa8O1sXXf2NV5qGJ/9/Vq8PVWCZuezADa1F0Vr2TaB8BseZIW+rhmEmLC2FfCdxj9NmLp00SilRTm40Hxm",
    "privateJsonWebKeyData": {
      "kty": "EC",
      "crv": "P-256",
      "x": "5dBlWvDtbF139jVeahif_f1avD1VgmbnswA2tRdFa9k",
      "y": "NoHwGx5khb6uGYSYsLYV8J3GP02YunTRKKVFObjQfGY",
      "d": "3aTiZ7odKAODYk4BpZlzulBCB_BptmxjtvrzyXI71Uw"
    },
    "publicRawKeyData":
        "BHiIXxrwhM92v4ueDrj3x1JJY4uS+II/IJPjqMvaKj/QfoOllnEkrnaOW1owBYRBMnP0pPouPkqbVfPACMUsfKs=",
    "publicSpkiKeyData":
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeIhfGvCEz3a/i54OuPfHUklji5L4gj8gk+Ooy9oqP9B+g6WWcSSudo5bWjAFhEEyc/Sk+i4+SptV88AIxSx8qw==",
    "publicJsonWebKeyData": {
      "kty": "EC",
      "crv": "P-256",
      "x": "eIhfGvCEz3a_i54OuPfHUklji5L4gj8gk-Ooy9oqP9A",
      "y": "foOllnEkrnaOW1owBYRBMnP0pPouPkqbVfPACMUsfKs"
    },
    "derivedBits": "WA==",
    "derivedLength": 7,
    "importKeyParams": {"curve": "p-256"},
    "deriveParams": {}
  },
  {
    "name": "generated at 2020-01-22T23:24:39",
    "privatePkcs8KeyData":
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg5AWOpgxJFPrYFT35Cd9NzjY/42GMqXHjN2u7nr4vTxmhRANCAAQ6JX8rvqAWaBf62fiBWeRSQ4VmSFtbXiBeMPlW7kvdm+CYn5qysrOmwWQF7ozYqksgU2rq/VxiOIDEA/0jwKih",
    "privateJsonWebKeyData": {
      "kty": "EC",
      "crv": "P-256",
      "x": "OiV_K76gFmgX-tn4gVnkUkOFZkhbW14gXjD5Vu5L3Zs",
      "y": "4JifmrKys6bBZAXujNiqSyBTaur9XGI4gMQD_SPAqKE",
      "d": "5AWOpgxJFPrYFT35Cd9NzjY_42GMqXHjN2u7nr4vTxk"
    },
    "publicRawKeyData":
        "BCjk7bfchTtYegPTteeUP+MrjJKfV7MqOZXFoS1GixVyRhk7MGC0Sc+2mdO1b3P1vR0F9l1pEk1hZfrbPdRs10U=",
    "publicSpkiKeyData":
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKOTtt9yFO1h6A9O155Q/4yuMkp9Xsyo5lcWhLUaLFXJGGTswYLRJz7aZ07Vvc/W9HQX2XWkSTWFl+ts91GzXRQ==",
    "publicJsonWebKeyData": {
      "kty": "EC",
      "crv": "P-256",
      "x": "KOTtt9yFO1h6A9O155Q_4yuMkp9Xsyo5lcWhLUaLFXI",
      "y": "Rhk7MGC0Sc-2mdO1b3P1vR0F9l1pEk1hZfrbPdRs10U"
    },
    "derivedBits": "iZA=",
    "derivedLength": 15,
    "importKeyParams": {"curve": "p-256"},
    "deriveParams": {}
  },

  // TODO: generate on firefox, once the import/export pkcs8 has been figured out
];
