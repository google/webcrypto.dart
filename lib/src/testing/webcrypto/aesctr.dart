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

library;

import 'dart:typed_data';

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
  generateKey: (generateKeyPairParams) =>
      AesCtrSecretKey.generateKey(generateKeyPairParams['length']),
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

void main() async {
  log('generate AES-CTR test case');
  await runner.generate(
    generateKeyParams: {'length': 256},
    importKeyParams: {},
    encryptDecryptParams: {
      'counter': bytesToJson(List.generate(16, (i) => 0xfe)),
      'length': 9,
    },
    maxPlaintext: 80,
  );
  log('--------------------');

  await runner.tests().runTests();
}

// Allow single quotes for hardcoded testData written as JSON:
// ignore_for_file: prefer_single_quotes
final _zeroAesCtrBlock = bytesToJson(Uint8List(16));
final _largeZeroAesCtrPlaintext = bytesToJson(Uint8List(4097));

final _testData = [
  {
    "name": "A128CTR/64 generated on boringssl/linux at 2020-01-19T16:40:39",
    "privateRawKeyData": "VPhdE6z4820SUnBmesDBSw==",
    "privateJsonWebKeyData": {
      "kty": "oct",
      "use": "enc",
      "alg": "A128CTR",
      "k": "VPhdE6z4820SUnBmesDBSw",
    },
    "plaintext": "dXJpcyBxdWlzIG1hdHRpcyBtYXNzYS4gUGhhc2VsbHVzIGNvbnZhbGxp",
    "ciphertext": "LnHSulNxQ6y+Z2rC2g8QQURwQWrI53qMPajfaef3cA0jaL+yAd3syGfz",
    "importKeyParams": {},
    "encryptDecryptParams": {
      "counter": "AAEECRAZJDFAUWR5kKnE4Q==",
      "length": 64,
    },
  },
  {
    "name": "A128CTR/64 generated on chrome/linux at 2020-01-19T16:40:46",
    "privateRawKeyData": "sx/x9PWRAq+IjUKJOGpDVA==",
    "privateJsonWebKeyData": {
      "kty": "oct",
      "alg": "A128CTR",
      "k": "sx_x9PWRAq-IjUKJOGpDVA",
    },
    "plaintext":
        "RXRpYW0gc3VzY2lwaXQgZXN0IHZlbCBoZW5kcmVyaXQgYmxhbmRpdC4gTnVsbGFt",
    "ciphertext":
        "LiahUAh0wPHi2GfXs9RjESf7Govs9Rc4EZvJQ1SB1qM/vYdIznBSXHkBUw5SyoM3",
    "importKeyParams": {},
    "encryptDecryptParams": {
      "counter": "AAEECRAZJDFAUWR5kKnE4Q==",
      "length": 64,
    },
  },
  {
    "name": "A128CTR/64 generated on firefox/linux at 2020-01-19T16:40:51",
    "privateRawKeyData": "tauul1rFz1pQSzowPHc1Bg==",
    "privateJsonWebKeyData": {
      "kty": "oct",
      "alg": "A128CTR",
      "k": "tauul1rFz1pQSzowPHc1Bg",
    },
    "plaintext": "bnQuIEluIGhlbmRyZXJpdCBwb3N1ZXJlIGxhY3VzIHZlbAp2YXJpdXMuIA==",
    "ciphertext":
        "Yvs4qLHAvfNP02lurZAX6khEG6YoARHFAvniYkn7olEh9/G21no8a/ksWA==",
    "importKeyParams": {},
    "encryptDecryptParams": {
      "counter": "AAEECRAZJDFAUWR5kKnE4Q==",
      "length": 64,
    },
  },
  {
    "name": "A256CTR/9 generated on boringssl/linux at 2020-01-21T22:27:46",
    "privateRawKeyData": "kytWTrsvIRYO8TqaGToZIAAys5BTxSk3rZ+uz97bcII=",
    "privateJsonWebKeyData": {
      "kty": "oct",
      "use": "enc",
      "alg": "A256CTR",
      "k": "kytWTrsvIRYO8TqaGToZIAAys5BTxSk3rZ-uz97bcII",
    },
    "plaintext": "dCBzYXBpZW4uIFBy",
    "ciphertext": "bSKocP19wU2keXkL",
    "importKeyParams": {},
    "encryptDecryptParams": {
      "counter": "/v7+/v7+/v7+/v7+/v7+/g==",
      "length": 9,
    },
  },
  {
    "name": "A256CTR/9 generated on chrome/linux at 2020-01-21T22:27:52",
    "privateRawKeyData": "WngeqRJDQN8vkhSxSPAM5+XQKqKZTv90uur/A5sX4Zk=",
    "privateJsonWebKeyData": {
      "kty": "oct",
      "alg": "A256CTR",
      "k": "WngeqRJDQN8vkhSxSPAM5-XQKqKZTv90uur_A5sX4Zk",
    },
    "plaintext":
        "IG5pYmguCgpTZWQgbW9sbGlzIHNhcGllbiBpbiBncmF2aWRhIGF1Y3Rvci4gQWVuZWFuIG5pYmggdG9ydG8=",
    "ciphertext":
        "Nj5naY4AWDSbh3taXM4k2Ys7gDlJJSmE4rBS2TQkYXf0DcO7G9pov5EQEXrrKk/LjGITblQI1GkCi9ndwl4=",
    "importKeyParams": {},
    "encryptDecryptParams": {
      "counter": "/v7+/v7+/v7+/v7+/v7+/g==",
      "length": 9,
    },
  },
  {
    "name": "A128CTR/128 4097-byte zero plaintext",
    "privateRawKeyData": _zeroAesCtrBlock,
    "privateJsonWebKeyData": {
      "kty": "oct",
      "use": "enc",
      "alg": "A128CTR",
      "k": "AAAAAAAAAAAAAAAAAAAAAA",
    },
    "plaintext": _largeZeroAesCtrPlaintext,
    "ciphertext": _largeAesCtrCiphertext,
    "importKeyParams": {},
    "encryptDecryptParams": {"counter": _zeroAesCtrBlock, "length": 128},
  },
  // HACK: Exclude counter rollover test data on Firefox, where it is broken:
  // https://hg.mozilla.org/projects/nss/file/38f1c92a5e1175bb8388768a209ac0efdabd1bd7/lib/freebl/ctr.c#l86
  ...(nullOnFirefox(_rolloverTestData) ?? <Map>[]),
];

const _largeAesCtrCiphertext =
    "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";

final _rolloverTestData = [
  {
    "name":
        "A128CTR/2 counter rollover, generated on boringssl/linux at 2020-01-21T22:17:08",
    "privateRawKeyData": "mkHLvTc/F5evWm7OAMz1Ag==",
    "privateJsonWebKeyData": {
      "kty": "oct",
      "use": "enc",
      "alg": "A128CTR",
      "k": "mkHLvTc_F5evWm7OAMz1Ag",
    },
    "plaintext":
        "cwpjb21tb2RvIGF0IHNpdCBhbWV0IG1pLiBQZWxsZW50ZXNxdWUgdmVoaWN1bGEgbA==",
    "ciphertext":
        "74m8tH2wT2MCrtw3Qr5SUTqfOPGUGzIeRnqB8psPFu4eujcjm2VgLv+LuJubZbrdkg==",
    "importKeyParams": {},
    "encryptDecryptParams": {
      "counter": "/v7+/v7+/v7+/v7+/v7+/g==",
      "length": 2,
    },
  },
  {
    "name":
        "A128CTR/2 counter rollover, generated chrome/linux at 2020-01-21T22:17:15",
    "privateRawKeyData": "ge2ewKf9LqaW1SHZnYYKTA==",
    "privateJsonWebKeyData": {
      "kty": "oct",
      "alg": "A128CTR",
      "k": "ge2ewKf9LqaW1SHZnYYKTA",
    },
    "plaintext":
        "UHJhZXNlbnQgZmVybWVudHVtIGVyYXQgdml0YWUgbGlndWxhCnByZXRpdW0gaW1wZQ==",
    "ciphertext":
        "elVwRCpfN3QT3om7mtNMvBWkPZfgla606PRdlEl529D7W7WDYz486NRVGlUI6qfJ8A==",
    "importKeyParams": {},
    "encryptDecryptParams": {
      "counter": "/v7+/v7+/v7+/v7+/v7+/g==",
      "length": 2,
    },
  },
];
