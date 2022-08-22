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

final runner = TestRunner.symmetric<AesGcmSecretKey>(
  algorithm: 'AES-GCM',
  importPrivateRawKey: (keyData, keyImportParams) =>
      AesGcmSecretKey.importRawKey(keyData),
  exportPrivateRawKey: (key) => key.exportRawKey(),
  importPrivatePkcs8Key: null, // not supported
  exportPrivatePkcs8Key: null,
  importPrivateJsonWebKey: (jsonWebKeyData, keyImportParams) =>
      AesGcmSecretKey.importJsonWebKey(jsonWebKeyData),
  exportPrivateJsonWebKey: (key) => key.exportJsonWebKey(),
  generateKey: (generateKeyPairParams) => AesGcmSecretKey.generateKey(
    generateKeyPairParams['length'],
  ),
  encryptBytes: (key, data, encryptParams) => key.encryptBytes(
    data,
    bytesFromJson(encryptParams, 'iv')!,
    additionalData: bytesFromJson(encryptParams, 'additionalData'),
    tagLength: encryptParams['length'] ?? 128,
  ),
  encryptStream: null, // not supported
  decryptBytes: (key, data, decryptParams) => key.decryptBytes(
    data,
    bytesFromJson(decryptParams, 'iv')!,
    additionalData: bytesFromJson(decryptParams, 'additionalData'),
    tagLength: decryptParams['length'] ?? 128,
  ),
  decryptStream: null, // not supported
  testData: _testData,
);

void main() {
  test('generate AES-GCM test case', () async {
    await runner.generate(
      generateKeyParams: {'length': 256},
      importKeyParams: {},
      encryptDecryptParams: {
        'iv': bytesToJson(List.generate(16, (i) => i * i)),
        'additionalData': bytesToJson(List.generate(32, (i) => i + 1)),
        'tagLength': 32,
      },
      maxPlaintext: 80,
      // TODO: Support test cases with invalid encryptDecryptParams for giving wrong additionalData
    );
  });

  runner.runTests();
}

// Allow single quotes for hardcoded testData written as JSON:
// ignore_for_file: prefer_single_quotes
final _testData = [
  {
    "name":
        "A128GCM/iv-only generated on boringssl/linux at 2020-01-21T22:52:27",
    "privateRawKeyData": "3nle6RpFx77jwrksoNUb1Q==",
    "privateJsonWebKeyData": {
      "kty": "oct",
      "use": "enc",
      "alg": "A128GCM",
      "k": "3nle6RpFx77jwrksoNUb1Q"
    },
    "plaintext":
        "dWx0cmljZXMKcG9zdWVyZSBjdWJpbGlhIEN1cmFlOyBBbGlxdWFtIHF1aXMgaGVuZHJlcml0IGxhY3VzLgo=",
    "ciphertext":
        "4FNVScf36O/F5uUwqA7qSKbDAhCDHaxdvYZmpViAbEY2GE2kYS18TFRVhfbY82T2JHfqOhIuMStKtHPOkmaB3pThaKK84ARXFj0xIL0b",
    "importKeyParams": {},
    "encryptDecryptParams": {"iv": "AAEECRAZJDFAUWR5kKnE4Q=="}
  },
  {
    "name": "A128GCM/iv-only generated chrome/linux at 2020-01-21T22:52:35",
    "privateRawKeyData": "oZGrqgGz6HAh13f4M+4nFw==",
    "privateJsonWebKeyData": {
      "kty": "oct",
      "alg": "A128GCM",
      "k": "oZGrqgGz6HAh13f4M-4nFw"
    },
    "plaintext": "c3QgbHVjdHVzLCB2ZWwgcGxhY2VyYQ==",
    "ciphertext": "/kdRoLGkAENcOsCcaBKevK+7dk+4WEQKiYFcsLIwq/IrxrpnZWA=",
    "importKeyParams": {},
    "encryptDecryptParams": {"iv": "AAEECRAZJDFAUWR5kKnE4Q=="}
  },
  {
    "name": "A128GCM/iv-only generated firefox/linux at 2020-01-21T22:52:41",
    "privateRawKeyData": "M1Y/cmVtV/58CgQeZ35lIQ==",
    "privateJsonWebKeyData": {
      "kty": "oct",
      "alg": "A128GCM",
      "k": "M1Y_cmVtV_58CgQeZ35lIQ"
    },
    "plaintext": "ZW5lYW4gbWFsZXN1YWRhIHVybmEgbm9uIA==",
    "ciphertext": "NggIpWUaQI3KtEbTba5eL4iytpEsP2Et7wEM4GwG+gqxz13BQdENxlU=",
    "importKeyParams": {},
    "encryptDecryptParams": {"iv": "AAEECRAZJDFAUWR5kKnE4Q=="}
  },
  {
    "name": "A128GCM/ad/64 generated on boringssl/linux at 2020-01-21T22:57:47",
    "privateRawKeyData": "vK/zU373WhzeojGh+qTDeQ==",
    "privateJsonWebKeyData": {
      "kty": "oct",
      "use": "enc",
      "alg": "A128GCM",
      "k": "vK_zU373WhzeojGh-qTDeQ"
    },
    "plaintext": "cmFlc2VudCBwcmV0aXVtIG4=",
    "ciphertext": "nelv0lgfowMjxTivj6R+MY8wpgejuOmZMVmlOFiFglov",
    "importKeyParams": {},
    "encryptDecryptParams": {
      "iv": "AAEECRAZJDFAUWR5kKnE4Q==",
      "additionalData": "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",
      "tagLength": 64
    }
  },
  {
    "name": "A128GCM/ad/64 generated on chrome/linux at 2020-01-21T22:57:56",
    "privateRawKeyData": "iPtcYDUi2Te9S1ysudhq3w==",
    "privateJsonWebKeyData": {
      "kty": "oct",
      "alg": "A128GCM",
      "k": "iPtcYDUi2Te9S1ysudhq3w"
    },
    "plaintext":
        "cnRhIGVyYXQuIFZlc3RpYnVsdW0gaW4gcG9ydHRpdG9yIHRlbGx1cy4KQWVuZWFuIGRpY3R1bSBkYXA=",
    "ciphertext":
        "rArO1JFccmd1hA5laU2FDaTkzuIvYGUEJcb1YLZun3ujGSq1+FqzMcpAvH8G2LBUT+1fTQE2bKbfXRSKpx5Swf2Gpzj3OeIRJmGK",
    "importKeyParams": {},
    "encryptDecryptParams": {
      "iv": "AAEECRAZJDFAUWR5kKnE4Q==",
      "additionalData": "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",
      "tagLength": 64
    }
  },
  {
    "name": "A128GCM/ad/64 generated on firefox/linux at 2020-01-21T22:58:03",
    "privateRawKeyData": "QROjT6fk9NlF5im+libUqw==",
    "privateJsonWebKeyData": {
      "kty": "oct",
      "alg": "A128GCM",
      "k": "QROjT6fk9NlF5im-libUqw"
    },
    "plaintext": "dHVyCmFsaXF1ZXQsIGRvbG9yIA==",
    "ciphertext": "eE4yhoSZIoIaTIn30tRZdONgB1SixHisBgVeBUWR7MllYSg=",
    "importKeyParams": {},
    "encryptDecryptParams": {
      "iv": "AAEECRAZJDFAUWR5kKnE4Q==",
      "additionalData": "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",
      "tagLength": 64
    }
  },
  {
    "name": "A256GCM/ad/32 generated on boringssl/linux at 2020-01-21T22:59:19",
    "privateRawKeyData": "uIfV8fgL3cR69VFEZBwFVKZYAEWRGl3k6JlT6mGAd1o=",
    "privateJsonWebKeyData": {
      "kty": "oct",
      "use": "enc",
      "alg": "A256GCM",
      "k": "uIfV8fgL3cR69VFEZBwFVKZYAEWRGl3k6JlT6mGAd1o"
    },
    "plaintext": "bnNlY3RldHVyCmFsaXF1ZXQsIGRvbG9yIGF1Z3VlIG1vbGVzdGk=",
    "ciphertext":
        "zxdrW+0Znsxkm6C1tOAEOGOKw4e4LvlQaoL47GrTL7VTCZicg1TRmdPeAwSnIIpIU+qztQA/",
    "importKeyParams": {},
    "encryptDecryptParams": {
      "iv": "AAEECRAZJDFAUWR5kKnE4Q==",
      "additionalData": "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",
      "tagLength": 32
    }
  },
  {
    "name": "A256GCM/ad/32 generated on chrome/linux at 2020-01-21T22:59:28",
    "privateRawKeyData": "P2GOjX4WcWt4NwlMhR4G7OLHWJQGDrTB37Igc4A+RTo=",
    "privateJsonWebKeyData": {
      "kty": "oct",
      "alg": "A256GCM",
      "k": "P2GOjX4WcWt4NwlMhR4G7OLHWJQGDrTB37Igc4A-RTo"
    },
    "plaintext": "ZG9sb3IgYW50ZSBzaXQgYW1ldCBzYXBpZW4uIFN1c3BlbmRpc3NlIHJo",
    "ciphertext":
        "NUV6Pcucshq2CUxOwM/isGmafoeInE2NOpiPXjqyz2Aqp/fJW8ufiDB2SuPdvcheHWhRrBRzA7O93w==",
    "importKeyParams": {},
    "encryptDecryptParams": {
      "iv": "AAEECRAZJDFAUWR5kKnE4Q==",
      "additionalData": "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",
      "tagLength": 32
    }
  },
  {
    "name": "A256GCM/ad/32 generated on firefox/linux at 2020-01-21T22:59:34",
    "privateRawKeyData": "gJMT676kwkWxVBe6Hq1RW4q27ek79VZOIZr4OSe0kmk=",
    "privateJsonWebKeyData": {
      "kty": "oct",
      "alg": "A256GCM",
      "k": "gJMT676kwkWxVBe6Hq1RW4q27ek79VZOIZr4OSe0kmk"
    },
    "plaintext":
        "bSBlZmZpY2l0dXIgcmlzdXMsIG5lYyBncmF2aWRhIHB1cnVzIGNvbmd1ZSBzZWQuIEFlbmVhbiBxdWlzIG5p",
    "ciphertext":
        "oR2a9eomXCftPdvZsK0XiolAnvCClLDCRVBpiaqETvXMMJfkqiJCmCofl8At/UjlaO/x8oYsK7caKXreYEUunExo1gq/IMALPLJMm8euzQ==",
    "importKeyParams": {},
    "encryptDecryptParams": {
      "iv": "AAEECRAZJDFAUWR5kKnE4Q==",
      "additionalData": "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",
      "tagLength": 32
    }
  }
];
