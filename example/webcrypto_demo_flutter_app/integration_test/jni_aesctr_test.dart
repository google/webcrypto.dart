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

import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:webcrypto/webcrypto.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('public API AES-128-CTR encryption matches known vector', (
    _,
  ) async {
    final key = await AesCtrSecretKey.importRawKey(
      base64Decode('VPhdE6z4820SUnBmesDBSw=='),
    );
    final plaintext = base64Decode(
      'dXJpcyBxdWlzIG1hdHRpcyBtYXNzYS4gUGhhc2VsbHVzIGNvbnZhbGxp',
    );
    final counter = base64Decode('AAEECRAZJDFAUWR5kKnE4Q==');
    final ciphertext = await key.encryptBytes(plaintext, counter, 64);

    expect(
      base64Encode(ciphertext),
      'LnHSulNxQ6y+Z2rC2g8QQURwQWrI53qMPajfaef3cA0jaL+yAd3syGfz',
    );
    expect(await key.decryptBytes(ciphertext, counter, 64), plaintext);
  });
}
