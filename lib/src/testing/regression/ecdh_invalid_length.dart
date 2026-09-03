// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import 'package:webcrypto/webcrypto.dart';

import '../utils/utils.dart';

final _cases = [
  (curve: EllipticCurve.p256, maxLength: 256),
  (curve: EllipticCurve.p384, maxLength: 384),
  (curve: EllipticCurve.p521, maxLength: 528),
];

List<({String name, Future<void> Function() test})> tests() => [
  for (final (:curve, :maxLength) in _cases)
    (
      name: 'ECDH rejects invalid lengths for $curve',
      test: () async {
        final alice = await EcdhPrivateKey.generateKey(curve);
        final bob = await EcdhPrivateKey.generateKey(curve);

        await _expectOperationError(
          alice.privateKey.deriveBits(maxLength + 1, bob.publicKey),
        );

        if (curve == EllipticCurve.p256) {
          await _expectArgumentError(
            alice.privateKey.deriveBits(-1, bob.publicKey),
          );
          for (final length in [
            0xfffffff9,
            0xffffffff,
            0x100000000,
            0x100000001,
          ]) {
            await _expectOperationError(
              alice.privateKey.deriveBits(length, bob.publicKey),
            );
          }
        }
      },
    ),
];

Future<void> _expectArgumentError(Future<List<int>> operation) async {
  var threw = false;
  try {
    await operation;
  } on ArgumentError {
    threw = true;
  }
  check(threw, 'Expected ArgumentError for invalid ECDH length');
}

Future<void> _expectOperationError(Future<List<int>> operation) async {
  var threw = false;
  try {
    await operation;
  } on OperationError {
    threw = true;
  }
  check(threw, 'Expected OperationError for invalid ECDH length');
}
