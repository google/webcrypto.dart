// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import 'package:test/test.dart';
import 'package:webcrypto/webcrypto.dart';
import '../utils/utils.dart';
import '../utils/testrunner.dart';
import '../utils/detected_runtime.dart';

final runner = TestRunner.asymmetric<EcdsaPrivateKey, EcdsaPublicKey>(
  algorithm: 'ECDSA',
  importPrivateRawKey: null, // not supported
  exportPrivateRawKey: null,
  // HACK: PKCS8 is not support for ECDH / ECDSA on firefox:
  // https://bugzilla.mozilla.org/show_bug.cgi?id=1133698
  //
  // So filter away PKCS8 test data and functions when running on gecko.
  importPrivatePkcs8Key: nullOnFirefox((keyData, keyImportParams) =>
      EcdsaPrivateKey.importPkcs8Key(keyData, curveFromJson(keyImportParams))),
  exportPrivatePkcs8Key: nullOnFirefox((key) => key.exportPkcs8Key()),
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
  testData: _testData.map((c) => {
        ...c,
        'privatePkcs8KeyData': nullOnFirefox(c['privatePkcs8KeyData']),
      }),
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
  runner.runTests();
}

// Allow single quotes for hardcoded testData written as JSON:
// ignore_for_file: prefer_single_quotes
final _testData = [
  {
    "name": "test key generation",
    "generateKeyParams": {"curve": "p-256"},
    "plaintext":
        "dXNjaXBpdCBhdCB2ZWhpY3VsYQppZCwgdmVzdGlidWx1bSBuZWMgbmlzbC4gRHVpcyBlcmF0IG5pc2ksIHJob25jdQ==",
    "importKeyParams": {"curve": "p-256"},
    "signVerifyParams": {"hash": "sha-256"}
  },
  {
    "name": "generated on boringssl/linux at 2020-01-14T18:35:09",
    "generateKeyParams": null,
    "privateRawKeyData": null,
    "privatePkcs8KeyData":
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg0lrDqshZTukBhbY2YzW+Ao/SAshmHtYHDbDYh2KBJEahRANCAAQSyzwDVpPkRxJFC1DhPNOmbNriaiO8ZJ0Y7JcyFdUgQrZqC6pL6QUJhk+KGzleTXl7FdySmRo3j2xFglUxIwO+",
    "privateJsonWebKeyData": {
      "kty": "EC",
      "use": "sig",
      "crv": "P-256",
      "x": "Ess8A1aT5EcSRQtQ4TzTpmza4mojvGSdGOyXMhXVIEI",
      "y": "tmoLqkvpBQmGT4obOV5NeXsV3JKZGjePbEWCVTEjA74",
      "d": "0lrDqshZTukBhbY2YzW-Ao_SAshmHtYHDbDYh2KBJEY"
    },
    "publicRawKeyData":
        "BBLLPANWk+RHEkULUOE806Zs2uJqI7xknRjslzIV1SBCtmoLqkvpBQmGT4obOV5NeXsV3JKZGjePbEWCVTEjA74=",
    "publicSpkiKeyData":
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEss8A1aT5EcSRQtQ4TzTpmza4mojvGSdGOyXMhXVIEK2aguqS+kFCYZPihs5Xk15exXckpkaN49sRYJVMSMDvg==",
    "publicJsonWebKeyData": {
      "kty": "EC",
      "use": "sig",
      "crv": "P-256",
      "x": "Ess8A1aT5EcSRQtQ4TzTpmza4mojvGSdGOyXMhXVIEI",
      "y": "tmoLqkvpBQmGT4obOV5NeXsV3JKZGjePbEWCVTEjA74"
    },
    "plaintext":
        "IHBvc3VlcmUgbGFjdXMgdmVsCnZhcml1cy4gSW4gZWdldCBtZXR1cyBsaWJlcm8uIEluIGhhYyBoYWJpdGFzc2UgcGxh",
    "signature":
        "BJodpIHbPhlgp31lzMAjb85i/4n5WIa2697Ac/9zpwL+RG65QsiYBIopeuiYl1yIu3BB4mgRHVpEP+7qAWl65Q==",
    "importKeyParams": {"curve": "p-256"},
    "signVerifyParams": {"hash": "sha-256"}
  },
  {
    "name": "generated on chrome/linux at 2020-01-14T18:35:52",
    "generateKeyParams": null,
    "privateRawKeyData": null,
    "privatePkcs8KeyData":
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgnG/CKsDXeXSwGY10JcaO/nIjXJAVRUDKJqDE6JWssL2hRANCAASXqnOzPTkUtewW9Qes4LwGH4FlshA83/jzEAwVx3yFrzGMtSr9QdWZHIE7Vqzc4Tg6y7wj3ml0PtsGiNyi2SBd",
    "privateJsonWebKeyData": {
      "kty": "EC",
      "crv": "P-256",
      "x": "l6pzsz05FLXsFvUHrOC8Bh-BZbIQPN_48xAMFcd8ha8",
      "y": "MYy1Kv1B1ZkcgTtWrNzhODrLvCPeaXQ-2waI3KLZIF0",
      "d": "nG_CKsDXeXSwGY10JcaO_nIjXJAVRUDKJqDE6JWssL0"
    },
    "publicRawKeyData":
        "BJeqc7M9ORS17Bb1B6zgvAYfgWWyEDzf+PMQDBXHfIWvMYy1Kv1B1ZkcgTtWrNzhODrLvCPeaXQ+2waI3KLZIF0=",
    "publicSpkiKeyData":
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEl6pzsz05FLXsFvUHrOC8Bh+BZbIQPN/48xAMFcd8ha8xjLUq/UHVmRyBO1as3OE4Osu8I95pdD7bBojcotkgXQ==",
    "publicJsonWebKeyData": {
      "kty": "EC",
      "crv": "P-256",
      "x": "l6pzsz05FLXsFvUHrOC8Bh-BZbIQPN_48xAMFcd8ha8",
      "y": "MYy1Kv1B1ZkcgTtWrNzhODrLvCPeaXQ-2waI3KLZIF0"
    },
    "plaintext":
        "ZGlnbmlzc2ltIHBoYXJldHJhLiBWaXZhbXVzIHB1bHZpbmFyIGxpYmVybyBvZGlvLiBQZWxsZW50ZXM=",
    "signature":
        "iwcez6+9FzkZXVHq+fwCP09i4NVnCdh7Cq5E5P0O1G40fgaewBvxIUHPiTdc4wjFCAOfR/OQ5zC+Y/SNzGnwLQ==",
    "importKeyParams": {"curve": "p-256"},
    "signVerifyParams": {"hash": "sha-256"}
  }
  // TODO: generate on firefox, once the import/export pkcs8 has been figured out
];
