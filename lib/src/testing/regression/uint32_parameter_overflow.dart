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

import 'package:webcrypto/webcrypto.dart';

// Browser backends enforce these ranges through Web IDL. These tests cover
// integer narrowing at the native FFI boundary.
const _isFfi = bool.fromEnvironment('dart.library.ffi');
const _maxUnsignedLong = 0xffffffff;

List<({String name, Future<void> Function() test})> tests() => !_isFfi
    ? const []
    : [
        (
          name: 'PBKDF2 rejects iteration counts above unsigned long',
          test: () async {
            final key = await Pbkdf2SecretKey.importRawKey([1, 2, 3, 4]);

            for (final iterations in [
              _maxUnsignedLong + 1,
              _maxUnsignedLong + 2,
            ]) {
              await _expectArgumentError(
                () =>
                    key.deriveBits(256, Hash.sha256, [5, 6, 7, 8], iterations),
                'Expected PBKDF2 iterations $iterations to be rejected',
              );
            }
          },
        ),
        (
          name: 'RSA-PSS rejects salt lengths that narrow at the FFI boundary',
          test: () async {
            final pair = await RsaPssPrivateKey.generateKey(
              1024,
              BigInt.from(65537),
              Hash.sha256,
            );
            final message = [1, 2, 3, 4];
            final signature = await pair.privateKey.signBytes(message, 0);

            for (final saltLength in [
              0x80000000,
              _maxUnsignedLong,
              _maxUnsignedLong + 1,
              _maxUnsignedLong + 2,
            ]) {
              await _expectArgumentError(
                () => pair.privateKey.signBytes(message, saltLength),
                'Expected RSA-PSS signing salt length $saltLength to be rejected',
              );

              await _expectArgumentError(
                () =>
                    pair.publicKey.verifyBytes(signature, message, saltLength),
                'Expected RSA-PSS verification salt length $saltLength to be rejected',
              );
            }
          },
        ),
      ];

Future<void> _expectArgumentError(
  Future<Object?> Function() callback,
  String message,
) async {
  try {
    await callback();
  } on ArgumentError {
    return;
  }
  throw AssertionError(message);
}
