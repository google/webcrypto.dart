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

library aesctr_test;

import 'package:test/test.dart';
import 'package:webcrypto/webcrypto.dart';
import '../utils/utils.dart';
import '../utils/testrunner.dart';
import '../utils/detected_runtime.dart';

final runner = TestRunner.symmetric<AesCtrSecretKey>(
  algorithm: 'AES-CTR',
  importPrivateRawKey: (keyData, keyImportParams) =>
      AesCtrSecretKey.importRawKey(keyData),
  exportPrivateRawKey: (key) => key.exportRawKey(),
  importPrivatePkcs8Key: null, // not supported
  exportPrivatePkcs8Key: null,
  importPrivateJsonWebKey: (jsonWebKeyData, keyImportParams) =>
      AesCtrSecretKey.importJsonWebKey(jsonWebKeyData),
  exportPrivateJsonWebKey: (key) => key.exportJsonWebKey(),
  generateKey: (generateKeyPairParams) => AesCtrSecretKey.generateKey(
    generateKeyPairParams['length'],
  ),
  encryptBytes: (key, data, encryptParams) => key.encryptBytes(
    data,
    bytesFromJson(encryptParams, 'counter')!,
    encryptParams['length'],
  ),
  encryptStream: (key, data, encryptParams) => key.encryptStream(
    data,
    bytesFromJson(encryptParams, 'counter')!,
    encryptParams['length'],
  ),
  decryptBytes: (key, data, decryptParams) => key.decryptBytes(
    data,
    bytesFromJson(decryptParams, 'counter')!,
    decryptParams['length'],
  ),
  decryptStream: (key, data, decryptParams) => key.decryptStream(
    data,
    bytesFromJson(decryptParams, 'counter')!,
    decryptParams['length'],
  ),
  testData: _testData,
);

void main() {
  test('generate AES-CTR test case', () async {
    await runner.generate(
      generateKeyParams: {'length': 256},
      importKeyParams: {},
      encryptDecryptParams: {
        'counter': bytesToJson(List.generate(16, (i) => 0xfe)),
        'length': 9,
      },
      maxPlaintext: 80,
    );
  });

  runner.runTests();
}

// Allow single quotes for hardcoded testData written as JSON:
// ignore_for_file: prefer_single_quotes
final _testData = [
  {
    "name": "A128CTR/64 generated on boringssl/linux at 2020-01-19T16:40:39",
    "privateRawKeyData": "VPhdE6z4820SUnBmesDBSw==",
    "privateJsonWebKeyData": {
      "kty": "oct",
      "use": "enc",
      "alg": "A128CTR",
      "k": "VPhdE6z4820SUnBmesDBSw"
    },
    "plaintext": "dXJpcyBxdWlzIG1hdHRpcyBtYXNzYS4gUGhhc2VsbHVzIGNvbnZhbGxp",
    "ciphertext": "LnHSulNxQ6y+Z2rC2g8QQURwQWrI53qMPajfaef3cA0jaL+yAd3syGfz",
    "importKeyParams": {},
    "encryptDecryptParams": {
      "counter": "AAEECRAZJDFAUWR5kKnE4Q==",
      "length": 64
    }
  },
  {
    "name": "A128CTR/64 generated on chrome/linux at 2020-01-19T16:40:46",
    "privateRawKeyData": "sx/x9PWRAq+IjUKJOGpDVA==",
    "privateJsonWebKeyData": {
      "kty": "oct",
      "alg": "A128CTR",
      "k": "sx_x9PWRAq-IjUKJOGpDVA"
    },
    "plaintext":
        "RXRpYW0gc3VzY2lwaXQgZXN0IHZlbCBoZW5kcmVyaXQgYmxhbmRpdC4gTnVsbGFt",
    "ciphertext":
        "LiahUAh0wPHi2GfXs9RjESf7Govs9Rc4EZvJQ1SB1qM/vYdIznBSXHkBUw5SyoM3",
    "importKeyParams": {},
    "encryptDecryptParams": {
      "counter": "AAEECRAZJDFAUWR5kKnE4Q==",
      "length": 64
    }
  },
  {
    "name": "A128CTR/64 generated on firefox/linux at 2020-01-19T16:40:51",
    "privateRawKeyData": "tauul1rFz1pQSzowPHc1Bg==",
    "privateJsonWebKeyData": {
      "kty": "oct",
      "alg": "A128CTR",
      "k": "tauul1rFz1pQSzowPHc1Bg"
    },
    "plaintext": "bnQuIEluIGhlbmRyZXJpdCBwb3N1ZXJlIGxhY3VzIHZlbAp2YXJpdXMuIA==",
    "ciphertext":
        "Yvs4qLHAvfNP02lurZAX6khEG6YoARHFAvniYkn7olEh9/G21no8a/ksWA==",
    "importKeyParams": {},
    "encryptDecryptParams": {
      "counter": "AAEECRAZJDFAUWR5kKnE4Q==",
      "length": 64
    }
  },
  {
    "name": "A256CTR/9 generated on boringssl/linux at 2020-01-21T22:27:46",
    "privateRawKeyData": "kytWTrsvIRYO8TqaGToZIAAys5BTxSk3rZ+uz97bcII=",
    "privateJsonWebKeyData": {
      "kty": "oct",
      "use": "enc",
      "alg": "A256CTR",
      "k": "kytWTrsvIRYO8TqaGToZIAAys5BTxSk3rZ-uz97bcII"
    },
    "plaintext": "dCBzYXBpZW4uIFBy",
    "ciphertext": "bSKocP19wU2keXkL",
    "importKeyParams": {},
    "encryptDecryptParams": {"counter": "/v7+/v7+/v7+/v7+/v7+/g==", "length": 9}
  },
  {
    "name": "A256CTR/9 generated on chrome/linux at 2020-01-21T22:27:52",
    "privateRawKeyData": "WngeqRJDQN8vkhSxSPAM5+XQKqKZTv90uur/A5sX4Zk=",
    "privateJsonWebKeyData": {
      "kty": "oct",
      "alg": "A256CTR",
      "k": "WngeqRJDQN8vkhSxSPAM5-XQKqKZTv90uur_A5sX4Zk"
    },
    "plaintext":
        "IG5pYmguCgpTZWQgbW9sbGlzIHNhcGllbiBpbiBncmF2aWRhIGF1Y3Rvci4gQWVuZWFuIG5pYmggdG9ydG8=",
    "ciphertext":
        "Nj5naY4AWDSbh3taXM4k2Ys7gDlJJSmE4rBS2TQkYXf0DcO7G9pov5EQEXrrKk/LjGITblQI1GkCi9ndwl4=",
    "importKeyParams": {},
    "encryptDecryptParams": {"counter": "/v7+/v7+/v7+/v7+/v7+/g==", "length": 9}
  },
  // HACK: Exclude counter rollover test data on Firefox, where it is broken:
  // https://hg.mozilla.org/projects/nss/file/38f1c92a5e1175bb8388768a209ac0efdabd1bd7/lib/freebl/ctr.c#l86
  ...(nullOnFirefox(_rolloverTestData) ?? <Map>[]),
];

final _rolloverTestData = [
  {
    "name":
        "A128CTR/2 counter rollover, generated on boringssl/linux at 2020-01-21T22:17:08",
    "privateRawKeyData": "mkHLvTc/F5evWm7OAMz1Ag==",
    "privateJsonWebKeyData": {
      "kty": "oct",
      "use": "enc",
      "alg": "A128CTR",
      "k": "mkHLvTc_F5evWm7OAMz1Ag"
    },
    "plaintext":
        "cwpjb21tb2RvIGF0IHNpdCBhbWV0IG1pLiBQZWxsZW50ZXNxdWUgdmVoaWN1bGEgbA==",
    "ciphertext":
        "74m8tH2wT2MCrtw3Qr5SUTqfOPGUGzIeRnqB8psPFu4eujcjm2VgLv+LuJubZbrdkg==",
    "importKeyParams": {},
    "encryptDecryptParams": {"counter": "/v7+/v7+/v7+/v7+/v7+/g==", "length": 2}
  },
  {
    "name":
        "A128CTR/2 counter rollover, generated chrome/linux at 2020-01-21T22:17:15",
    "privateRawKeyData": "ge2ewKf9LqaW1SHZnYYKTA==",
    "privateJsonWebKeyData": {
      "kty": "oct",
      "alg": "A128CTR",
      "k": "ge2ewKf9LqaW1SHZnYYKTA"
    },
    "plaintext":
        "UHJhZXNlbnQgZmVybWVudHVtIGVyYXQgdml0YWUgbGlndWxhCnByZXRpdW0gaW1wZQ==",
    "ciphertext":
        "elVwRCpfN3QT3om7mtNMvBWkPZfgla606PRdlEl529D7W7WDYz486NRVGlUI6qfJ8A==",
    "importKeyParams": {},
    "encryptDecryptParams": {"counter": "/v7+/v7+/v7+/v7+/v7+/g==", "length": 2}
  },
];
