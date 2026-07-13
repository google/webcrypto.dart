// Copyright 2026 Google LLC
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

import 'package:webcrypto/webcrypto.dart';
import '../utils/utils.dart';

List<({String name, Future<void> Function() test})> tests() => [
  (
    name: 'ECDH derives an empty secret when length is zero',
    test: () async {
      final alice = await EcdhPrivateKey.generateKey(EllipticCurve.p256);
      final bob = await EcdhPrivateKey.generateKey(EllipticCurve.p256);

      final secret = await alice.privateKey.deriveBits(0, bob.publicKey);

      check(secret.isEmpty, 'Expected an empty ECDH secret');
    },
  ),
  (
    name: 'PBKDF2 derives an empty secret when length is zero',
    test: () async {
      final key = await Pbkdf2SecretKey.importRawKey(Uint8List(16));

      final secret = await key.deriveBits(0, Hash.sha256, Uint8List(16), 1);

      check(secret.isEmpty, 'Expected an empty PBKDF2 secret');
    },
  ),
];
