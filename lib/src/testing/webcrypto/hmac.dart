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

import 'package:webcrypto/webcrypto.dart';
import '../utils/utils.dart';
import '../utils/testrunner.dart';
import 'package:test/test.dart';

final runner = TestRunner.symmetric<HmacSecretKey>(
  algorithm: 'HMAC',
  importPrivateRawKey: (keyData, keyImportParams) =>
      HmacSecretKey.importRawKey(keyData, hashFromJson(keyImportParams)),
  exportPrivateRawKey: (key) => key.exportRawKey(),
  importPrivatePkcs8Key: null, // not supported
  exportPrivatePkcs8Key: null,
  importPrivateJsonWebKey: (jsonWebKeyData, keyImportParams) =>
      HmacSecretKey.importJsonWebKey(
          jsonWebKeyData, hashFromJson(keyImportParams)),
  exportPrivateJsonWebKey: (key) => key.exportJsonWebKey(),
  generateKey: (generateKeyPairParams) => HmacSecretKey.generateKey(
    hashFromJson(generateKeyPairParams),
    length: generateKeyPairParams['length'], // may be null
  ),
  signBytes: (key, data, signParams) => key.signBytes(data),
  signStream: (key, data, signParams) => key.signStream(data),
  verifyBytes: (key, signature, data, verifyParams) =>
      key.verifyBytes(signature, data),
  verifyStream: (key, signature, data, verifyParams) =>
      key.verifyStream(signature, data),
  testData: _testData,
);

void main() {
  test('generate HMAC test case', () async {
    await runner.generate(
      generateKeyParams: {'hash': hashToJson(Hash.sha384), 'length': 512},
      importKeyParams: {'hash': hashToJson(Hash.sha384), 'length': 512},
      signVerifyParams: {},
      maxPlaintext: 80,
    );
  });

  runner.runTests();
}

// Allow single quotes for hardcoded testData written as JSON:
// ignore_for_file: prefer_single_quotes
final _testData = [
  {
    "name": "HS256 generated on boringssl/linux at 2020-01-17T17:22:02",
    "privateRawKeyData": "hJOnqFnCbZUjWwItPd5l1YW9mWC5jjjYT6h5twHEUdU=",
    "privateJsonWebKeyData": {
      "kty": "oct",
      "use": "sig",
      "alg": "HS256",
      "k": "hJOnqFnCbZUjWwItPd5l1YW9mWC5jjjYT6h5twHEUdU"
    },
    "plaintext": "YXRlYSBkaWM=",
    "signature": "XNHqkq5E4mJ5cbSoRGJI/Nop7pYeb9tAzajzXC0HB8U=",
    "importKeyParams": {"hash": "sha-256"},
    "signVerifyParams": {}
  },
  {
    "name": "HS256 generated on chrome/linux at 2020-01-17T17:22:15",
    "privateRawKeyData":
        "EAACHGiD/ybP+Q/+lcoSUcLmm1D64wN8OUVPhyKfsFMAC7QgcyFAWm8QIyyKsCKzHf/FJMNYtW1WZXAejpoN5g==",
    "privateJsonWebKeyData": {
      "kty": "oct",
      "alg": "HS256",
      "k":
          "EAACHGiD_ybP-Q_-lcoSUcLmm1D64wN8OUVPhyKfsFMAC7QgcyFAWm8QIyyKsCKzHf_FJMNYtW1WZXAejpoN5g"
    },
    "plaintext":
        "IGJsYW5kaXQgZWdldCwgcG9ydHRpdG9yIGEgb2Rpby4KQWxpcXVhbSBtYXR0aXMgZ3JhdmlkYSB2aXZlcnJhLiBQZWxsZW50ZXNxdWUgdQ==",
    "signature": "AusmDrNk4hWUNpyIgVVNJ/fGKKwipprpa0t9JnuOBMQ=",
    "importKeyParams": {"hash": "sha-256"},
    "signVerifyParams": {}
  },
  {
    "name": "HS256 generated on firefox/linux at 2020-01-17T17:22:22",
    "privateRawKeyData":
        "wcdaqRxznwwshJa+JX9yWIWQfzk72zX+hAX3+dGg61flkEGxf4+QAYbPJ/kXQ3I/AHFmciS1ET2IYDefx90BPw==",
    "privateJsonWebKeyData": {
      "kty": "oct",
      "alg": "HS256",
      "k":
          "wcdaqRxznwwshJa-JX9yWIWQfzk72zX-hAX3-dGg61flkEGxf4-QAYbPJ_kXQ3I_AHFmciS1ET2IYDefx90BPw"
    },
    "plaintext":
        "dWxhLApxdWlzIHBvcnRhIGFyY3Ugc2NlbGVyaXNxdWUuIFNlZCBmZWxpcyBkb2xvciwgdWx0cmljaWVzIGV1IGR1aSBhdCwg",
    "signature": "xnRlZ0cGFck6p30kMt3c4Z1GnKA+Ek99wK9nS8xRmmk=",
    "importKeyParams": {"hash": "sha-256"},
    "signVerifyParams": {}
  },
  {
    "name": "HS384/512 generated on boringssl/linux at 2020-01-17T17:27:08",
    "privateRawKeyData":
        "M5FlV0ooh9jtDA+ULhcnRpcbbhrhPTqoPPJMMpIvkpTZAetpJ2nbseRmyDLiuiS4Ea79zF8DJkAcnYrI/2ouDA==",
    "privateJsonWebKeyData": {
      "kty": "oct",
      "use": "sig",
      "alg": "HS384",
      "k":
          "M5FlV0ooh9jtDA-ULhcnRpcbbhrhPTqoPPJMMpIvkpTZAetpJ2nbseRmyDLiuiS4Ea79zF8DJkAcnYrI_2ouDA"
    },
    "plaintext":
        "dCBuaXNsLiBQcmFlc2VudCBlbmltIG1hZ25hLApyaG9uY3VzIHF1aXMgY29uZGltZW50dW0gYWMs",
    "signature":
        "Dc6Jiw5A+92IB4RAJh96Y9acoyZgrx75FmFa2Ye3+h+DihU+qiUyTXiuTOrSi53g",
    "importKeyParams": {"hash": "sha-384", "length": 512},
    "signVerifyParams": {}
  },
  {
    "name": "HS384/512 generated on chrome/linux at 2020-01-17T17:27:15",
    "privateRawKeyData":
        "pBLSDxNWRIpFxODNstC+Cd+n+e0ABp38wwbALA5o+wJ+r5mgIrLChbKoWmt3zVMWEjDR/qBaHsTuG7kVmnOW9w==",
    "privateJsonWebKeyData": {
      "kty": "oct",
      "alg": "HS384",
      "k":
          "pBLSDxNWRIpFxODNstC-Cd-n-e0ABp38wwbALA5o-wJ-r5mgIrLChbKoWmt3zVMWEjDR_qBaHsTuG7kVmnOW9w"
    },
    "plaintext": "aXQgcXVpcy4gQ3U=",
    "signature":
        "CZCQz8y18FtWhyzxofYSk47cV/KJjFESt4dR+luhPrMop5cW7QmJTreRLFM4RTKy",
    "importKeyParams": {"hash": "sha-384", "length": 512},
    "signVerifyParams": {}
  },
  {
    "name": "HS384/512 generated on firefox/linux at 2020-01-17T17:27:21",
    "privateRawKeyData":
        "xJAxNE2TmomHP+xMSi2hEAHjTPTPNKBACiepH3ijfglWbIVFP3wckj7bQ7QSXvCklewu6ao3HeNUu/kVvdDnJg==",
    "privateJsonWebKeyData": {
      "kty": "oct",
      "alg": "HS384",
      "k":
          "xJAxNE2TmomHP-xMSi2hEAHjTPTPNKBACiepH3ijfglWbIVFP3wckj7bQ7QSXvCklewu6ao3HeNUu_kVvdDnJg"
    },
    "plaintext": "YyBsYW9yZWV0LCBsZQ==",
    "signature":
        "bhnHVnnqoe1L9T7zHImrjDH4B4YVz+Qrvdfxw1eutajcDu2Plhr49B9GXNArXoS8",
    "importKeyParams": {"hash": "sha-384", "length": 512},
    "signVerifyParams": {}
  },
  {
    "name": "HS512/37 generated on boringssl/linux at 2020-01-17T17:23:41",
    "privateRawKeyData": "kuk/KhA=",
    "privateJsonWebKeyData": {
      "kty": "oct",
      "use": "sig",
      "alg": "HS512",
      "k": "kuk_KhA"
    },
    "plaintext":
        "bmEgaWQgbGliZXJvIGV1aXNtb2QKYWxpcXVldC4gTW9yYmkgYWNjdW1zYW4gZ3JhdmlkYSBkb2xvciwgbmVjIGVnZXN0YXMg",
    "signature":
        "LGncsixAXwdUxThwRwpMUobfBNI8dJvZ78DyRTwu3OrzzcwkA5PNgI1zGNWNTs5X2sxX960uY6bDIYjDlu0bGw==",
    "importKeyParams": {"hash": "sha-512", "length": 37},
    "signVerifyParams": {}
  },
  {
    "name": "HS512/37 generated chrome/linux at 2020-01-17T17:23:49",
    "privateRawKeyData": "fEqx17g=",
    "privateJsonWebKeyData": {"kty": "oct", "alg": "HS512", "k": "fEqx17g"},
    "plaintext": "ZHVpIG1hdXJpcy4gU2VkIHBoYXJldHJhLCBu",
    "signature":
        "ePa3V+068UE7exuKxgeoa/weVTKGnnYPkn2B6NDj23QGaoxYP2wuwoZW9rkCMtJ796pL9Xpa0YLlBYiMukrHCg==",
    "importKeyParams": {"hash": "sha-512", "length": 37},
    "signVerifyParams": {}
  },
  {
    "name": "HS512/37 generated on firefox/linux at 2020-01-17T17:23:56",
    "privateRawKeyData": "Ay0AcA==",
    "privateJsonWebKeyData": {"kty": "oct", "alg": "HS512", "k": "Ay0AcA"},
    "plaintext": "bSBtYXR0aXMgZ3JhdmlkYSB2aXZlcnJhLiBQZQ==",
    "signature":
        "WKl+Xj11ugyC0HGD4458P7vVEAllEyftMPnywgwZwwubW66a3sS+nsCgEBWI163m/ZZ9sUPR8QA0yVEhkVUrwQ==",
    "importKeyParams": {"hash": "sha-512", "length": 37},
    "signVerifyParams": {}
  },
];
