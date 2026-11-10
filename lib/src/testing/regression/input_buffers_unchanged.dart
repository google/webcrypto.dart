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

import '../utils/utils.dart';

List<({String name, Future<void> Function() test})> tests() => [
  (
    name: 'Hash byte operations leave caller input unchanged',
    test: () async {
      final data = List<int>.generate(8193, (i) => i & 0xff);
      final original = List<int>.of(data);
      for (final hash in [Hash.sha1, Hash.sha256, Hash.sha384, Hash.sha512]) {
        final digest = await hash.digestBytes(data);
        check(equalBytes(data, original));
        check(equalBytes(digest, await hash.digestBytes(data)));
      }
    },
  ),
  (
    name: 'AES-CBC byte operations leave data and IV unchanged',
    test: () async {
      final key = await AesCbcSecretKey.importRawKey(List<int>.filled(16, 0));
      final data = List<int>.generate(8193, (i) => i & 0xff);
      final original = List<int>.of(data);
      final iv = List<int>.generate(16, (i) => i);
      final originalIv = List<int>.of(iv);
      final ciphertext = await key.encryptBytes(data, iv);
      check(equalBytes(data, original));
      check(equalBytes(iv, originalIv));
      final savedCiphertext = List<int>.of(ciphertext);
      check(equalBytes(await key.decryptBytes(ciphertext, iv), original));
      check(equalBytes(ciphertext, savedCiphertext));
      check(equalBytes(iv, originalIv));
    },
  ),
  (
    name: 'HMAC byte and stream verification leave inputs unchanged',
    test: () async {
      final key = await HmacSecretKey.importRawKey([1, 2, 3], Hash.sha256);
      await _checkSigningInputs(
        key.signBytes,
        key.verifyBytes,
        key.verifyStream,
      );
    },
  ),
  (
    name: 'RSA-PSS byte and stream verification leave inputs unchanged',
    test: () async {
      final pair = await RsaPssPrivateKey.generateKey(
        2048,
        BigInt.from(65537),
        Hash.sha256,
      );
      await _checkSigningInputs(
        (data) => pair.privateKey.signBytes(data, 32),
        (signature, data) => pair.publicKey.verifyBytes(signature, data, 32),
        (signature, data) => pair.publicKey.verifyStream(signature, data, 32),
      );
    },
  ),
  (
    name: 'RSASSA-PKCS1-v1_5 verification leaves inputs unchanged',
    test: () async {
      final pair = await RsassaPkcs1V15PrivateKey.generateKey(
        2048,
        BigInt.from(65537),
        Hash.sha256,
      );
      await _checkSigningInputs(
        pair.privateKey.signBytes,
        pair.publicKey.verifyBytes,
        pair.publicKey.verifyStream,
      );
    },
  ),
  (
    name: 'ECDSA byte and stream verification leave inputs unchanged',
    test: () async {
      final pair = await EcdsaPrivateKey.generateKey(EllipticCurve.p256);
      await _checkSigningInputs(
        (data) => pair.privateKey.signBytes(data, Hash.sha256),
        (signature, data) =>
            pair.publicKey.verifyBytes(signature, data, Hash.sha256),
        (signature, data) =>
            pair.publicKey.verifyStream(signature, data, Hash.sha256),
      );
    },
  ),
];

Future<void> _checkSigningInputs(
  Future<List<int>> Function(List<int>) sign,
  Future<bool> Function(List<int>, List<int>) verifyBytes,
  Future<bool> Function(List<int>, Stream<List<int>>) verifyStream,
) async {
  final data = List<int>.generate(8193, (i) => i & 0xff);
  final original = List<int>.of(data);
  final signature = await sign(data);
  final originalSignature = List<int>.of(signature);
  check(equalBytes(data, original));
  check(await verifyBytes(signature, data));
  check(await verifyStream(signature, Stream.value(data)));
  check(equalBytes(data, original));
  check(equalBytes(signature, originalSignature));
  signature[0] ^= 1;
  final invalidSignature = List<int>.of(signature);
  check(!await verifyBytes(signature, data));
  check(!await verifyStream(signature, Stream.value(data)));
  check(equalBytes(signature, invalidSignature));
  check(equalBytes(data, original));
}
