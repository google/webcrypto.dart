// Copyright 2025 Google LLC
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

final runner = TestRunner.asymmetric<Ed25519PrivateKey, Ed25519PublicKey>(
  algorithm: 'Ed25519',
  importPrivateRawKey: null, // not supported
  exportPrivateRawKey: null,
  importPrivatePkcs8Key: (keyData, _) =>
      Ed25519PrivateKey.importPkcs8Key(keyData),
  exportPrivatePkcs8Key: (key) => key.exportPkcs8Key(),
  importPrivateJsonWebKey: (jsonWebKeyData, _) =>
      Ed25519PrivateKey.importJsonWebKey(jsonWebKeyData),
  exportPrivateJsonWebKey: (key) => key.exportJsonWebKey(),
  importPublicRawKey: (keyData, _) => Ed25519PublicKey.importRawKey(keyData),
  exportPublicRawKey: (key) => key.exportRawKey(),
  importPublicSpkiKey: (keyData, _) => Ed25519PublicKey.importSpkiKey(keyData),
  exportPublicSpkiKey: (key) => key.exportSpkiKey(),
  importPublicJsonWebKey: (jsonWebKeyData, _) =>
      Ed25519PublicKey.importJsonWebKey(jsonWebKeyData),
  exportPublicJsonWebKey: (key) => key.exportJsonWebKey(),
  generateKeyPair: (_) => Ed25519PrivateKey.generateKey(),
  signBytes: (key, data, _) => key.signBytes(data),
  verifyBytes: (key, signature, data, _) => key.verifyBytes(signature, data),
  testData: _testData,
);

void main() async {
  log('generate Ed25519 test case');
  await runner.generate(
    generateKeyParams: {},
    importKeyParams: {},
  );
  log('--------------------');

  await runner.tests().runTests();
}

// Allow single quotes for hardcoded testData written as JSON:
// ignore_for_file: prefer_single_quotes
final _testData = [
  {
    "name": "generated on boringssl/mac at 2025-10-10T14:38:47",
    "privatePkcs8KeyData":
        "MC4CAQAwBQYDK2VwBCIEIBEI/GyQ7Xh+wcPtrvvY2K9QaLU3cDVa5hCMrZW4bIVP",
    "privateJsonWebKeyData": {
      "kty": "OKP",
      "alg": "Ed25519",
      "crv": "Ed25519",
      "x": "ikNZOCnJK6CDQn2NRicyWxafv-LUqZtmjDEx_s9pezE",
      "d": "EQj8bJDteH7Bw-2u-9jYr1BotTdwNVrmEIytlbhshU8"
    },
    "publicRawKeyData": "ikNZOCnJK6CDQn2NRicyWxafv+LUqZtmjDEx/s9pezE=",
    "publicSpkiKeyData":
        "MCowBQYDK2VwAyEAikNZOCnJK6CDQn2NRicyWxafv+LUqZtmjDEx/s9pezE=",
    "publicJsonWebKeyData": {
      "kty": "OKP",
      "alg": "Ed25519",
      "crv": "Ed25519",
      "x": "ikNZOCnJK6CDQn2NRicyWxafv-LUqZtmjDEx_s9pezE"
    },
    "plaintext":
        "bnQgc29kYWxlcyBuZXF1ZSBpbiBpcHN1bSB0ZW1wb3IsIGV0IGZhdWNpYnVzIHR1cnBpcyB0cmlzdGlxdWUuIFNlZCBub24KcGxhY2VyYXQgZXJhdC4gU2VkIHF1YW0gdHVycGlzLCB0ZW1wdXMgaW4gYW50ZSBub24sIHNvZGFsZXMgc2NlbGVyaXNxdWUgcXVhbS4KQWxpcXVhbSB2aXRhZSBzYWdpdHRpcyBmZWxpcy4gT3JjaSB2YXJpdXMgbmF0b3F1ZSBwZW5hdGlidXMgZXQgbWFnbmlzIGRpcwpwYXJ0dXJpZW50IG1vbnRlcywgbmFzY2V0dXIgcmlkaWN1bHVzIG11cy4gTnVsbGFtIHRlbXBvciBlcmF0IG5vbiBibGFuZGl0CmVsZW1lbnR1bS4gUGhhc2VsbHVzIHZlbCBkaWFtIGZlbGlzLiBQcmFlc2VudCBmZXJtZW50dW0gZXJhdCB2aXRhZSBsaWd1bGEKcHJldGl1bSBpbXBlcmRpZXQuIFByb2luIGluIGxhY2luaWEgZXguIFNlZCBmZXVnaWF0IGVnZXN0YXMgbHVjdHVzLiBDcmFzCnBlbGxlbnRlc3F1ZSBvcmNpIHF1aXMgbWkgYXVjdG9yIGNvbW1vZG8uIEFlbmVhbiBzaXQgYW1ldCBsdWN0dXMgbGliZXJvLiBNb3JiaQpldSBlbGl0IHNlZCBsaWd1bGEgaGVuZHJlcml0IHN1c2NpcGl0LiBQcmFlc2VudCBmYWNpbGlzaXMgbmlzbCBhIG1hdXJpcyBjdXJzdXMKbW9sZXN0aWUuCgpQZWxsZW50ZXNxdWUgaGFiaXRhbnQgbW9yYmkgdHJpc3RpcXVlIHNlbmVjdHVzIGV0IG5ldHVzIGV0IG1hbGVzdWFkYSBmYW1lcyBhYwp0dXJwaXMgZWdlc3Rhcy4gQ3JhcyBsYWNpbmlhIGFudGUgYWMgbGFvcmVldCBzZW1wZXIuIE1vcmJpIGlhY3VsaXMgbG9ib3J0aXMKbWFzc2EsIHF1aXMgcGhhcmV0cmEgcHVydXMgY29tbW9kbyB2ZWwuIE51bGxhIHJob25jdXMgZW5pbSBuaWJoLCBhYyB1bHRyaWNlcwpsZWN0dXMgZWxlbWVudHVtIHV0LiBQcm9pbiBwZWxsZW50ZXNxdWUgbWF4aW11cyBldWlzbW9kLiBRdWlzcXVlIGNvbnZhbGxpcyBkdWkKYWMgbG9yZW0gc29kYWxlcyBwbGFjZXJhdC4gTnVuYyBhbGlxdWV0IHB1cnVzIGF0IGVyb3MgZWxlbWVudHVtIHNjZWxlcmlzcXVlIHF1aXMKZXQgbmVxdWUuIFZlc3RpYnVsdW0gbm9uIHB1cnVzIGludGVyZHVtLCB2b2x1dHBhdCBleCBzZWQsIHBsYWNlcmF0IGVsaXQuIE51bGxhbQpuZWMgdmVsaXQgdnVscHV0YXRlLCBzZW1wZXIgZG9sb3IgdXQsIG1hdHRpcyBwdXJ1cy4gTWFlY2VuYXMgYXQgaWFjdWxpcyBhdWd1ZS4KRG9uZWMgdGVtcG9yIG5pc2wgZXUgZmluaWJ1cyBjb25ndWUuCgpMb3JlbSBpcHN1bSBkb2xvciBzaXQgYW1ldCwgY29uc2VjdGV0dXIgYWRpcGlzY2luZyBlbGl0LiBEb25lYyBpbiBsb3JlbQppbXBlcmRpZXQsIGVsZWlmZW5kIGxvcmVtIGltcGVyZGlldCwgcG9ydGEgZXJhdC4gVmVzdGlidWx1bSBpbiBwb3J0dGl0b3IgdGVsbHVzLgpBZW5lYW4gZGljdHVtIGRhcGlidXMgbWFnbmEsIHZlbCB2ZW5lbmF0aXMgc2FwaWVuIHBvc3VlcmUgYXQuIEV0aWFtIGV1IGhlbmRyZXJpdApsYWN1cywgbmVjIHBvc3VlcmUgbGliZXJvLiBBZW5lYW4=",
    "signature":
        "SjQ/uXLEj5Y7/UsixNmKJov8zUCjzB4sXoRPgt/BHkt9BFkOY/69mE5h6/tykXOJ+i53TArW+JZxGCynswK1DA==",
    "importKeyParams": {},
    "signVerifyParams": {},
  },
];
