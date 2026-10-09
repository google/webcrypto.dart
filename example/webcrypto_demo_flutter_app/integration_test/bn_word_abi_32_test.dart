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

import 'dart:ffi' as ffi;

import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:webcrypto/webcrypto.dart';
import 'package:webcrypto/src/third_party/boringssl/generated_bindings.dart';

@ffi.Native<ffi.Int Function(ffi.Pointer<BIGNUM>, ffi.Uint64)>(
  assetId: 'package:webcrypto/webcrypto.dart',
  symbol: 'webcrypto_BN_set_word',
)
external int _bnSetWordWithOldBinding(ffi.Pointer<BIGNUM> word, int value);

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  test('BN_set_word uses the 32-bit native argument width', () {
    expect(ffi.Abi.current(), ffi.Abi.androidArm);
    expect(ffi.sizeOf<ffi.UintPtr>(), 4);

    final corrected = _readWord(BN_set_word);
    final old = _readWord(_bnSetWordWithOldBinding);
    expect(corrected, [0, 0, 0, 0, 0, 1, 0, 1]);
    expect(
      old,
      isNot(equals(corrected)),
      reason: 'The old binding unexpectedly passed the correct exponent.',
    );
  });

  test('RSA-OAEP generates a key with exponent 65537', () async {
    final pair = await RsaOaepPrivateKey.generateKey(
      2048,
      BigInt.from(65537),
      Hash.sha256,
    );
    final publicJwk = await pair.publicKey.exportJsonWebKey();
    expect(publicJwk['e'], 'AQAB');
  });
}

List<int> _readWord(int Function(ffi.Pointer<BIGNUM>, int) setWord) {
  final word = BN_new();
  expect(word, isNot(ffi.nullptr));
  try {
    final bytes = OPENSSL_malloc(8).cast<ffi.Uint8>();
    expect(bytes, isNot(ffi.nullptr));
    try {
      expect(setWord(word, 65537), 1);
      expect(BN_bn2bin_padded(bytes, 8, word), 1);
      return List<int>.from(bytes.asTypedList(8));
    } finally {
      OPENSSL_free(bytes.cast());
    }
  } finally {
    BN_free(word);
  }
}
