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
  final keyData = base64.encode([1]);
  group('expected operation errors', () {
    final invoked = <String>[];
    Future<T> fail<T>(String operation) async {
      invoked.add(operation);
      throw FormatException('invalid $operation');
    }

    final errorRunner = TestRunner.symmetric<String>(
      algorithm: 'test',
      importPrivateRawKey: (_, _) async => 'key',
      exportPrivateRawKey: (_) async => [],
      generateKey: (params) => params['invalid'] == true
          ? fail<String>('generateKey')
          : Future.value('key'),
      signBytes: (_, _, _) => fail<List<int>>('signBytes'),
      verifyBytes: (_, _, _, _) => fail<bool>('verifyBytes'),
      encryptBytes: (_, _, _) => fail<List<int>>('encryptBytes'),
      decryptBytes: (_, _, _) => fail<List<int>>('decryptBytes'),
      deriveBits: (_, _, _) => fail<List<int>>('deriveBits'),
    );

    final cases = <String, Map<String, dynamic>>{
      'generateKey': {
        'generateKeyParams': {'invalid': true},
      },
      'signBytes': {
        'plaintext': keyData,
        'signVerifyParams': <String, dynamic>{},
      },
      'verifyBytes': {
        'plaintext': keyData,
        'signature': keyData,
        'signVerifyParams': <String, dynamic>{},
      },
      'encryptBytes': {
        'plaintext': keyData,
        'encryptDecryptParams': <String, dynamic>{},
      },
      'decryptBytes': {
        'ciphertext': keyData,
        'encryptDecryptParams': <String, dynamic>{},
      },
      'deriveBits': {'derivedLength': 8, 'deriveParams': <String, dynamic>{}},
    };

    for (final entry in cases.entries) {
      test('${entry.key} checks its expected error', () async {
        invoked.clear();
        final isGeneration = entry.key == 'generateKey';
        final tests = errorRunner.tests(
          testData: [
            {
              'name': entry.key,
              if (!isGeneration) 'privateRawKeyData': keyData,
              if (!isGeneration) 'importKeyParams': <String, dynamic>{},
              'errorOperation': entry.key,
              'expectedErrorType': 'FormatException',
              'expectedErrorMessage': 'invalid ${entry.key}',
              ...entry.value,
            },
          ],
        );
        for (final testCase in tests) {
          await testCase.test();
        }
        expect(invoked, [entry.key]);
      });
    }

    test('a mismatched error type fails', () async {
      final tests = errorRunner.tests(
        testData: [
          {
            'name': 'wrong error',
            'generateKeyParams': {'invalid': true},
            'errorOperation': 'generateKey',
            'expectedErrorType': 'OperationError',
            'expectedErrorMessage': 'invalid generateKey',
          },
        ],
      );
      await tests.first.test();
      await expectLater(tests.last.test(), throwsA(isA<AssertionError>()));
    });

    test('a mismatched error message fails', () async {
      final tests = errorRunner.tests(
        testData: [
          {
            'name': 'wrong message',
            'generateKeyParams': {'invalid': true},
            'errorOperation': 'generateKey',
            'expectedErrorType': 'FormatException',
            'expectedErrorMessage': 'different message',
          },
        ],
      );
      await tests.first.test();
      await expectLater(tests.last.test(), throwsA(isA<AssertionError>()));
    });

    test('an operation that succeeds fails the error case', () async {
      final tests = errorRunner.tests(
        testData: [
          {
            'name': 'unexpected success',
            'generateKeyParams': <String, dynamic>{},
            'errorOperation': 'generateKey',
            'expectedErrorType': 'FormatException',
            'expectedErrorMessage': 'invalid generateKey',
          },
        ],
      );
      await tests.first.test();
      await expectLater(tests.last.test(), throwsA(isA<AssertionError>()));
    });

    test('rejects an error case with unused input', () async {
      final tests = errorRunner.tests(
        testData: [
          {
            'name': 'unused input',
            'generateKeyParams': {'invalid': true},
            'plaintext': keyData,
            'errorOperation': 'generateKey',
            'expectedErrorType': 'FormatException',
            'expectedErrorMessage': 'invalid generateKey',
          },
        ],
      );
      await expectLater(tests.single.test(), throwsA(isA<AssertionError>()));
    });
  });
}
