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

final runner = TestRunner.asymmetric<X25519PrivateKey, X25519PublicKey>(
  algorithm: 'X25519',
  importPrivateRawKey: null, // not supported
  exportPrivateRawKey: null,
  importPrivatePkcs8Key: (keyData, keyImportParams) =>
      X25519PrivateKey.importPkcs8Key(keyData),
  exportPrivatePkcs8Key: (key) => key.exportPkcs8Key(),
  importPrivateJsonWebKey: (jsonWebKeyData, keyImportParams) =>
      X25519PrivateKey.importJsonWebKey(jsonWebKeyData),
  exportPrivateJsonWebKey: (key) => key.exportJsonWebKey(),
  importPublicRawKey: (keyData, keyImportParams) =>
      X25519PublicKey.importRawKey(keyData),
  exportPublicRawKey: (key) => key.exportRawKey(),
  importPublicSpkiKey: (keyData, keyImportParams) =>
      X25519PublicKey.importSpkiKey(keyData),
  exportPublicSpkiKey: (key) => key.exportSpkiKey(),
  importPublicJsonWebKey: (jsonWebKeyData, keyImportParams) =>
      X25519PublicKey.importJsonWebKey(jsonWebKeyData),
  exportPublicJsonWebKey: (key) => key.exportJsonWebKey(),
  generateKeyPair: (generateKeyPairParams) async {
    // Use public / private keys from two different pairs, as if they had been
    // exchanged.
    final a = await X25519PrivateKey.generateKey();
    final b = await X25519PrivateKey.generateKey();
    return (
      privateKey: a.privateKey,
      publicKey: b.publicKey,
    );
  },
  deriveBits: (keys, length, deriveParams) => keys.privateKey.deriveBits(
    length,
    keys.publicKey,
  ),
  testData: _testData,
);

void main() async {
  log('generate X25519 test case');
  await runner.generate(
    generateKeyParams: {},
    importKeyParams: {},
    maxDeriveLength: 256,
  );
  log('--------------------');

  await runner.tests().runTests();
}

// Allow single quotes for hardcoded testData written as JSON:
// ignore_for_file: prefer_single_quotes
final _testData = [
  {
    "name": "generated on boringssl/mac at 2025-10-06T12:24:27",
    "privatePkcs8KeyData":
        "MC4CAQAwBQYDK2VuBCIEIOeCpzucGHA4bexZ1GZ7t4uAgIn21fihfYvrTXWdEd2A",
    "privateJsonWebKeyData": {
      "kty": "OKP",
      "crv": "X25519",
      "x": "V2VUjKPgzM3fjJDZ8FLsfcgYWMDEYexMCil_vQ8oJ2Q",
      "d": "54KnO5wYcDht7FnUZnu3i4CAifbV-KF9i-tNdZ0R3YA"
    },
    "publicRawKeyData": "Oun0StbIlmZsImGBVF8PrTzWyFhdqP5cKfapLeHIRRI=",
    "publicSpkiKeyData":
        "MCowBQYDK2VuAyEAOun0StbIlmZsImGBVF8PrTzWyFhdqP5cKfapLeHIRRI=",
    "publicJsonWebKeyData": {
      "kty": "OKP",
      "crv": "X25519",
      "x": "Oun0StbIlmZsImGBVF8PrTzWyFhdqP5cKfapLeHIRRI"
    },
    "derivedBits": "j671vmVMMI6R+ud2QxtiKjIwoQbPd66wskZklxA=",
    "derivedLength": 228,
    "importKeyParams": {},
    "deriveParams": {}
  }
];
