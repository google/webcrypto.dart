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
    name: 'RSA-PSS reports invalid saltLength through returned Futures',
    test: () async {
      final pair = await RsaPssPrivateKey.generateKey(
        1024,
        BigInt.from(65537),
        Hash.sha256,
      );
      const data = [1, 2, 3];
      const signature = <int>[];

      final operations = <String, Future<Object?> Function()>{
        'signBytes': () => pair.privateKey.signBytes(data, -1),
        'signStream': () => pair.privateKey.signStream(Stream.value(data), -1),
        'verifyBytes': () => pair.publicKey.verifyBytes(signature, data, -1),
        'verifyStream': () =>
            pair.publicKey.verifyStream(signature, Stream.value(data), -1),
      };

      for (final MapEntry(key: name, value: operation) in operations.entries) {
        await _expectAsyncArgumentError(name, operation);
      }
    },
  ),
];

Future<void> _expectAsyncArgumentError(
  String name,
  Future<Object?> Function() operation,
) async {
  late Future<Object?> result;
  try {
    result = operation();
  } catch (error) {
    throw AssertionError('$name threw synchronously: $error');
  }

  Object? error;
  try {
    await result;
  } catch (e) {
    error = e;
  }
  check(error is ArgumentError, '$name returned $error');
}
