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

final runner = TestRunner.symmetric<AesCbcSecretKey>(
  algorithm: 'AES-CBC',
  importPrivateRawKey: (keyData, keyImportParams) =>
      AesCbcSecretKey.importRawKey(keyData),
  exportPrivateRawKey: (key) => key.exportRawKey(),
  importPrivatePkcs8Key: null, // not supported
  exportPrivatePkcs8Key: null,
  importPrivateJsonWebKey: (jsonWebKeyData, keyImportParams) =>
      AesCbcSecretKey.importJsonWebKey(jsonWebKeyData),
  exportPrivateJsonWebKey: (key) => key.exportJsonWebKey(),
  generateKey: (generateKeyPairParams) => AesCbcSecretKey.generateKey(
    generateKeyPairParams['length'],
  ),
  encryptBytes: (key, data, encryptParams) =>
      key.encryptBytes(data, bytesFromJson(encryptParams, 'iv')!),
  encryptStream: (key, data, encryptParams) =>
      key.encryptStream(data, bytesFromJson(encryptParams, 'iv')!),
  decryptBytes: (key, data, decryptParams) =>
      key.decryptBytes(data, bytesFromJson(decryptParams, 'iv')!),
  decryptStream: (key, data, decryptParams) =>
      key.decryptStream(data, bytesFromJson(decryptParams, 'iv')!),
  testData: _testData,
);

void main() {
  test('generate AES-CBC test case', () async {
    await runner.generate(
      generateKeyParams: {'length': 256},
      importKeyParams: {},
      encryptDecryptParams: {
        'iv': bytesToJson(List.generate(16, (i) => i * i)),
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
    "name": "A128CBC generated on boringssl/linux at 2020-01-17T22:56:41",
    "privateRawKeyData": "nJ0IrxKwen1VN2/rfLsmmA==",
    "privateJsonWebKeyData": {
      "kty": "oct",
      "use": "enc",
      "alg": "A128CBC",
      "k": "nJ0IrxKwen1VN2_rfLsmmA"
    },
    "plaintext":
        "dmVzdGlidWx1bSBsdWN0dXMgZGlhbSwgcXVpcwppbnRlcmR1bSBsZW8gYWxpcXVhbSBhYy4gTnVuYyBhYyBtaSBpbiBs",
    "ciphertext":
        "MlBdzmsDQSRORkwayz7U9P7v87lgsVRRTrWsZi3qnWiqTW+m6K3KRQ4B1I1u+W7r/kBCBQt404253SV0DeIHNe/HUesVja7CB5jvJUQ6GmQ=",
    "importKeyParams": {},
    "encryptDecryptParams": {"iv": "AAEECRAZJDFAUWR5kKnE4Q=="}
  },
  {
    "name": "A128CBC generated on chrome/linux at 2020-01-17T22:56:49",
    "privateRawKeyData": "S9yXvDZ0nsH6cKF5+O6mfA==",
    "privateJsonWebKeyData": {
      "kty": "oct",
      "alg": "A128CBC",
      "k": "S9yXvDZ0nsH6cKF5-O6mfA"
    },
    "plaintext":
        "SW4gdml2ZXJyYSBzZW0gaWQgZXN0IHRpbmNpZHVudApkaWduaXNzaW0uIFBlbGxlbnRlc3F1ZSB0cmlzdGlxdWUsIG5pc2wgc2VkIGw=",
    "ciphertext":
        "1sh9WWx/u82vLF4BIFG4NtK9eRv8j11m9YkxP5iYpLyBcJn8YYboUM5GDJ3Jz7XO3MAIXO7EXlHcu1R9yaYWwsprjON/tDhjEhYuSGjIz8M=",
    "importKeyParams": {},
    "encryptDecryptParams": {"iv": "AAEECRAZJDFAUWR5kKnE4Q=="}
  },
  {
    "name": "A128CBC generated on firefox/linux at 2020-01-17T22:56:55",
    "privateRawKeyData": "o4QOi2ASkWTf5W9tCLSkAw==",
    "privateJsonWebKeyData": {
      "kty": "oct",
      "alg": "A128CBC",
      "k": "o4QOi2ASkWTf5W9tCLSkAw"
    },
    "plaintext": "dWUgc2VtcGVyIGp1c3RvIG9yY2ksIHZpdGFlCnZlbmVuYXRp",
    "ciphertext":
        "Apckyp9bxHAVpo0+MAlAgtcWAa6JZz9OdT/WGskcTVd/e542dAZJ88byiZ2So+2U",
    "importKeyParams": {},
    "encryptDecryptParams": {"iv": "AAEECRAZJDFAUWR5kKnE4Q=="}
  },
  {
    "name": "A256CBC generated on boringssl/linux at 2020-01-17T22:59:11",
    "privateRawKeyData": "b0y6+MqS0ShCvZiloJJAeG8ei8tVIN3OCYIdn1FN74o=",
    "privateJsonWebKeyData": {
      "kty": "oct",
      "use": "enc",
      "alg": "A256CBC",
      "k": "b0y6-MqS0ShCvZiloJJAeG8ei8tVIN3OCYIdn1FN74o"
    },
    "plaintext":
        "Z2V0IGZlbGlzLiBWZXN0aWJ1bHVtIHZlc3RpYnVsdW0gbHVjdHVzIGRpYW0sIHF1aQ==",
    "ciphertext":
        "V8tNAuLWzVMZElQGnNysrBdH6BSRmL1Ui5v5OE6iAqkeI9So2RriGhWbkko9YMtz58qwW70EmVCA4wCM29zAjg==",
    "importKeyParams": {},
    "encryptDecryptParams": {"iv": "AAEECRAZJDFAUWR5kKnE4Q=="}
  },
  {
    "name": "A256CBC generated on chrome/linux at 2020-01-17T22:59:19",
    "privateRawKeyData": "QGCU25fcU5zkTZyaQjX7cAbMCLw+elW/QxwzWzPz74c=",
    "privateJsonWebKeyData": {
      "kty": "oct",
      "alg": "A256CBC",
      "k": "QGCU25fcU5zkTZyaQjX7cAbMCLw-elW_QxwzWzPz74c"
    },
    "plaintext": "bGlzLCBhdWd1ZSBtYWduYSBtYXhpbXVzCm5lcQ==",
    "ciphertext": "EvgXzycWuyiHl72eTX6u2dKKrq2afchTzy5ipVd0DxE=",
    "importKeyParams": {},
    "encryptDecryptParams": {"iv": "AAEECRAZJDFAUWR5kKnE4Q=="}
  },
  {
    "name": "A256CBC generated on firefox/linux at 2020-01-17T22:59:24",
    "privateRawKeyData": "1mfFKdMKMTCHSbor0ZzCLJJoUR5VUZ6Io+ypUuBeAWI=",
    "privateJsonWebKeyData": {
      "kty": "oct",
      "alg": "A256CBC",
      "k": "1mfFKdMKMTCHSbor0ZzCLJJoUR5VUZ6Io-ypUuBeAWI"
    },
    "plaintext": "c2NlIGEgdmVsaXQgY29tbW9kbywgbGFvcmVldCBuaXNsIGV0LA==",
    "ciphertext":
        "pjuEkxaRURuXYdb4vMgTJboTw9aFYOYYS10AoqJx4QYb3wDg6yzCec/LpGpqaPXY",
    "importKeyParams": {},
    "encryptDecryptParams": {"iv": "AAEECRAZJDFAUWR5kKnE4Q=="}
  },
];
