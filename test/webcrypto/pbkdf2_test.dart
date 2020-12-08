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

import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webcrypto/webcrypto.dart';
import '../utils/utils.dart';
import '../utils/testrunner.dart';

/// Utility to hold both [Pbkdf2SecretKey] and [rawKeyData], such that we can
/// fake an implementation of `exportPrivaterawKey` for [TestRunner].
class _ExportablePbkdf2SecretKey {
  final Pbkdf2SecretKey pbkdf2SecretKey;
  final List<int> rawKeyData;
  _ExportablePbkdf2SecretKey(this.pbkdf2SecretKey, this.rawKeyData);
}

final runner = TestRunner.symmetric<_ExportablePbkdf2SecretKey>(
  algorithm: 'PBKDF2',
  importPrivateRawKey: (keyData, keyImportParams) async {
    return _ExportablePbkdf2SecretKey(
      await Pbkdf2SecretKey.importRawKey(keyData),
      keyData,
    );
  },
  // Not really support by [Pbkdf2SecretKey] but required by [TestRunner].
  exportPrivateRawKey: (key) async => key.rawKeyData,
  importPrivatePkcs8Key: null, // not supported
  exportPrivatePkcs8Key: null,
  importPrivateJsonWebKey: null,
  exportPrivateJsonWebKey: null,
  generateKey: (generateKeyPairParams) async {
    final rawKeyData = Uint8List(generateKeyPairParams['length']);
    fillRandomBytes(rawKeyData);
    return _ExportablePbkdf2SecretKey(
      await Pbkdf2SecretKey.importRawKey(rawKeyData),
      rawKeyData,
    );
  },
  deriveBits: (key, length, deriveParams) => key.pbkdf2SecretKey.deriveBits(
    length,
    hashFromJson(deriveParams),
    bytesFromJson(deriveParams, 'salt')!,
    deriveParams['iterations'],
  ),
  testData: _testData,
);

void main() {
  test('generate Pbkdf2SecretKey test case', () async {
    await runner.generate(
      generateKeyParams: {'length': 91},
      importKeyParams: {},
      deriveParams: {
        'hash': hashToJson(Hash.sha256),
        'salt': bytesToJson(List.generate(42, (i) => (i + i) % 256)),
        'iterations': 2000
      },
      minDeriveLength: 256,
      maxDeriveLength: 256,
    );
  });

  runner.runTests();
}

// Allow single quotes for hardcoded testData written as JSON:
// ignore_for_file: prefer_single_quotes
final _testData = [
  {
    "name": "SHA-384/2/512 generated on boringssl/linux at 2020-01-26T20:46:06",
    "privateRawKeyData": "kxoGkUuBRbVcRFx6TmdwN952GvTCwYxBoPkPdhTdZw==",
    "derivedBits":
        "p6koJ5irMF5b7HqfsYPG/RCqFTC2jApFGn9EUkYVRzSI/8eAHg8mVZ/L6AG8JB2c5Vi6WLXS6A4ZG05wTGZQjw==",
    "derivedLength": 512,
    "importKeyParams": {},
    "deriveParams": {
      "hash": "sha-384",
      "salt": "AAIEBggKDA4QEhQWGBocHiA=",
      "iterations": 2
    }
  },
  {
    "name": "SHA-384/2/512 generated on chrome/linux at 2020-01-26T20:46:17",
    "privateRawKeyData": "MzZMAfbcm45AcEFWCCp463xBXfsM3kUGbfwvHbwZGA==",
    "derivedBits":
        "OgAQ5edJsYjLrp33lhp1PLObJ8EEyE10xU/BwNvv88DFFE/5eFEZZ4sCoywz7U/pib85M5C/S822YqWCqWcNhg==",
    "derivedLength": 512,
    "importKeyParams": {},
    "deriveParams": {
      "hash": "sha-384",
      "salt": "AAIEBggKDA4QEhQWGBocHiA=",
      "iterations": 2
    }
  },
  {
    "name": "SHA-384/2/512 generated on firefox/linux at 2020-01-26T20:46:22",
    "privateRawKeyData": "lvpsUi3gpPiyRqBAKRZHgXqyyiAFi1qEi5c0iWqpBw==",
    "derivedBits":
        "A3d1xewG2vpDCPGUwtUD0vnxvAttR5ooe1oo07Tn2kRwEGr8oY2UT0fCoKdT4zDgNQuGPYTJ2dAX1s7nFjMxCw==",
    "derivedLength": 512,
    "importKeyParams": {},
    "deriveParams": {
      "hash": "sha-384",
      "salt": "AAIEBggKDA4QEhQWGBocHiA=",
      "iterations": 2
    }
  },
  {
    "name":
        "SHA-256/200/2048 generated on boringssl/linux at 2020-01-26T20:51:19",
    "privateRawKeyData": "yyMsKhVOxc9PHza86irjtXRi8UALVNFG",
    "derivedBits":
        "X8ErmooBkBYk+OtYy4KheRfqUMgTo8r9ZhxN/A5jpcMJ3LPRLrwBLLo12gFlfp/O9G68pGaqM5+dZ1AseHxCDRU9cUh5PHtP8VoihXT4+xjLroAS2C8QaXAdn7gpfSwZhORmUPIeilWtfp2ylD9qpChrCw3uIN23pfDQyGL516API+HEguWuk0JRBZQqAhtuuLN2fWjXXtEFTXBaeKqdKxguog9FNzjfjvBXc9hdbbBkr7e49nlV67SB+EbzbcV0sPL76cIXYW/97BdYcmR9wYHaFHZy0PQt0p0YglVtS1XzVYTX+qpi76gZvRV199NQTotQ0F0Lv3qljak/Am4Bjg==",
    "derivedLength": 2048,
    "importKeyParams": {},
    "deriveParams": {
      "hash": "sha-256",
      "salt":
          "AAIEBggKDA4QEhQWGBocHiAiJCYoKiwuMDI0Njg6PD5AQkRGSEpMTlBSVFZYWlxeYGJkZmhqbG5wcnR2eHp8foCChA==",
      "iterations": 200
    }
  },
  {
    "name": "SHA-256/200/2048 generated on chrome/linux at 2020-01-26T20:51:28",
    "privateRawKeyData": "3CRm+aqhHKKVOkjwxO5a39u+4dLh+bZU",
    "derivedBits":
        "xkxmTIGP23MjiztNyiit1+2SDoQtx/FAhXBPaeFUW55gI2rtJ4HMjhX8oMH17Ito275PHlEVDayNZ+JEgmlvL/UzRjEjGmkWLEDtlbVkewg7gZruJJOaizTVbYdTXnB4cYePkRhgimVT0yPKzWT5ncC75b8nhmDBw7E1hpcs4JqOtoRrz2+ZduU6sKrbXU9p47JiZVi4utNhn+GtrTIGzSZpadB01M56BOuHNcSWeP8lb1ck/pL7Af0csWRvKwU1YMlCp0HGnwUxzhpMPU7kWE9JsPBK5VdTQD0zKciRu8G6njCdmUECFKnx/+9YcAmLGD6GubnN1q+k5P2iPFoAAg==",
    "derivedLength": 2048,
    "importKeyParams": {},
    "deriveParams": {
      "hash": "sha-256",
      "salt":
          "AAIEBggKDA4QEhQWGBocHiAiJCYoKiwuMDI0Njg6PD5AQkRGSEpMTlBSVFZYWlxeYGJkZmhqbG5wcnR2eHp8foCChA==",
      "iterations": 200
    }
  },
  {
    "name":
        "SHA-256/200/2048 generated on firefox/linux at 2020-01-26T20:51:34",
    "privateRawKeyData": "t2CEEuWQLzK8X4/VdvWSXeM0rs7CqEoZ",
    "derivedBits":
        "hYwPZLpZLY/85GYy5dmgDFlaAGVDOc6a+185CzHT9lzmbvyr/va0BdetlaKlLp0oDEMFk/T+pbTGiXbO77w72MAZ4Ex5TEEwHS1SbCLBl3eNpww2Hp3GNbR99XytzRJXspTVCHcI4myH77XSroqLHmrcMOBG+hzPPldeGAIot884m+xE1sSQ2tciwr5BGaDYm70vHoRrrA7V/DMLcBVwe0vLXdTYRJ+MJA7m49AcvMNIHuG4IcFH8YjBQJzpBr9AAvoWrjCi2aShL9fiUICciSo/xHWMhwxmd1ey0zQHTR+pRgJvn2cfWQ8j2yvM/2brZZ4DXvLqsMspRsANNeSPYQ==",
    "derivedLength": 2048,
    "importKeyParams": {},
    "deriveParams": {
      "hash": "sha-256",
      "salt":
          "AAIEBggKDA4QEhQWGBocHiAiJCYoKiwuMDI0Njg6PD5AQkRGSEpMTlBSVFZYWlxeYGJkZmhqbG5wcnR2eHp8foCChA==",
      "iterations": 200
    }
  },
  {
    "name":
        "SHA-256/2000/256 generated on boringssl/linux at 2020-01-26T20:53:30",
    "privateRawKeyData":
        "4XkbSK7qF2Y8VJRFPK9IKwlsaESTJakBb6W4iRzh0tUz0vRK1vPtKpbXUWyYYdVmgIsJyErlj6Bs7fBkk4emxMHiibHBtITzB4cxTv445WFbxZ0z6U1133XKIw==",
    "derivedBits": "X6TgJrH/g3gdofA8uXIUNjc3vW/aS+8Ujcl5Hwf2P7k=",
    "derivedLength": 256,
    "importKeyParams": {},
    "deriveParams": {
      "hash": "sha-256",
      "salt": "AAIEBggKDA4QEhQWGBocHiAiJCYoKiwuMDI0Njg6PD5AQkRGSEpMTlBS",
      "iterations": 2000
    }
  },
  {
    "name": "SHA-256/2000/256 generated on chrome/linux at 2020-01-26T20:53:37",
    "privateRawKeyData":
        "T4mukl1lWjzS31gfkv8+lNOJXS30EKQhgeX6aE4tJkZAC9fxokxRwtNZwf0R94Rm4BkNCsb19w2zV2hZBi9/Eb3CsYpZr3zUOdybqZDxLGlSQcXE2y4jgAb7Dw==",
    "derivedBits": "P+pCuZlUMVi0AbTNPPcJK6+vdDzGeufWue6v3lp0v9s=",
    "derivedLength": 256,
    "importKeyParams": {},
    "deriveParams": {
      "hash": "sha-256",
      "salt": "AAIEBggKDA4QEhQWGBocHiAiJCYoKiwuMDI0Njg6PD5AQkRGSEpMTlBS",
      "iterations": 2000
    }
  },
  {
    "name":
        "SHA-256/2000/256 generated on firefox/linux at 2020-01-26T20:53:43",
    "privateRawKeyData":
        "P9W0f/ILv4mv45XGQh5DRy5anxkPqjVa6aPbEIgUvUsVqR0XwKlpCGYDkOuEeCKSemUC39ucWCEs1i/pqIy7mXSCpKvxVFKxCaAglSlBGZrCHD4jbxaGuTdelg==",
    "derivedBits": "gWWgqU5qtNl9UFTdGBAYThixXoYDbnxkXbQLSuD4zys=",
    "derivedLength": 256,
    "importKeyParams": {},
    "deriveParams": {
      "hash": "sha-256",
      "salt": "AAIEBggKDA4QEhQWGBocHiAiJCYoKiwuMDI0Njg6PD5AQkRGSEpMTlBS",
      "iterations": 2000
    }
  },
];
