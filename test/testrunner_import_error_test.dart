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

import 'package:test/test.dart';
import 'package:webcrypto/src/testing/utils/testrunner.dart';

void main() {
  final calls = <String>[];
  Future<String> fail(String format) async {
    calls.add(format);
    throw FormatException('invalid $format key');
  }

  Future<String> checkParamsAndFail(
    String format,
    Map<String, dynamic> params,
  ) {
    expect(params['tag'], 'passed');
    return fail(format);
  }

  final runner = TestRunner.asymmetric<String, String>(
    algorithm: 'test',
    importPrivateRawKey: (_, params) =>
        checkParamsAndFail('private raw', params),
    exportPrivateRawKey: (_) async => [],
    importPrivatePkcs8Key: (_, params) =>
        checkParamsAndFail('private pkcs8', params),
    exportPrivatePkcs8Key: (_) async => [],
    importPrivateJsonWebKey: (_, params) =>
        checkParamsAndFail('private jwk', params),
    exportPrivateJsonWebKey: (_) async => {},
    importPublicRawKey: (_, params) => checkParamsAndFail('public raw', params),
    exportPublicRawKey: (_) async => [],
    importPublicSpkiKey: (_, params) =>
        checkParamsAndFail('public spki', params),
    exportPublicSpkiKey: (_) async => [],
    importPublicJsonWebKey: (_, params) =>
        checkParamsAndFail('public jwk', params),
    exportPublicJsonWebKey: (_) async => {},
    generateKeyPair: (_) async => (privateKey: '', publicKey: ''),
  );

  final keyData = base64.encode([1]);
  final formats = <String, Object>{
    'privateRawKeyData': keyData,
    'privatePkcs8KeyData': keyData,
    'privateJsonWebKeyData': <String, dynamic>{},
    'publicRawKeyData': keyData,
    'publicSpkiKeyData': keyData,
    'publicJsonWebKeyData': <String, dynamic>{},
  };

  test('checks all six key import formats independently', () async {
    calls.clear();
    final cases = formats.entries.map(
      (entry) => <String, dynamic>{
        'name': entry.key,
        'importKeyParams': <String, dynamic>{'tag': 'passed'},
        'importKeyException': 'FormatException: invalid',
        entry.key: entry.value,
      },
    );
    final tests = runner.tests(testData: cases);
    expect(tests.length, 12);
    for (final testCase in tests) {
      await testCase.test();
    }
    expect(calls, [
      'private raw',
      'private pkcs8',
      'private jwk',
      'public raw',
      'public spki',
      'public jwk',
    ]);
  });

  test('successful import fails an expected error case', () async {
    final successfulRunner = TestRunner.symmetric<String>(
      algorithm: 'test',
      importPrivateRawKey: (_, _) async => 'key',
      exportPrivateRawKey: (_) async => [],
      generateKey: (_) async => 'key',
    );
    final tests = successfulRunner.tests(
      testData: [
        {
          'name': 'unexpected success',
          'privateRawKeyData': keyData,
          'importKeyParams': <String, dynamic>{},
          'importKeyException': 'FormatException',
        },
      ],
    );
    await tests.first.test();
    await expectLater(tests.last.test(), throwsA(isA<AssertionError>()));
  });

  test('different import error fails an expected error case', () async {
    final tests = runner.tests(
      testData: [
        {
          'name': 'wrong error',
          'privateRawKeyData': keyData,
          'importKeyParams': <String, dynamic>{'tag': 'passed'},
          'importKeyException': 'OperationError',
        },
      ],
    );
    await tests.first.test();
    await expectLater(tests.last.test(), throwsA(isA<AssertionError>()));
  });

  test('rejects error cases with unused operation data', () async {
    final tests = runner.tests(
      testData: [
        {
          'name': 'invalid error case',
          'privateRawKeyData': keyData,
          'importKeyParams': <String, dynamic>{},
          'importKeyException': 'FormatException',
          'plaintext': keyData,
        },
      ],
    );
    await expectLater(tests.single.test(), throwsA(isA<AssertionError>()));
  });
}
