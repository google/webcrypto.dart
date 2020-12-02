// Copyright 2020 Google LLC
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

import 'utils/utils.dart';
import 'utils/testrunner.dart' show TestRunner;
import 'package:test/test.dart' show test;

// TestRunner implementations
import 'webcrypto/aescbc_test.dart' as aescbc_test;
import 'webcrypto/aesctr_test.dart' as aesctr_test;
import 'webcrypto/aesgcm_test.dart' as aesgcm_test;
import 'webcrypto/ecdh_test.dart' as ecdh_test;
import 'webcrypto/ecdsa_test.dart' as ecdsa_test;
import 'webcrypto/hkdf_test.dart' as hkdf_test;
import 'webcrypto/hmac_test.dart' as hmac_test;
import 'webcrypto/pbkdf2_test.dart' as pbkdf2_test;
import 'webcrypto/rsaoaep_test.dart' as rsaoaep_test;
import 'webcrypto/rsapss_test.dart' as rsapss_test;
import 'webcrypto/rsassapkcs1v15_test.dart' as rsassapkcs1v15_test;

// Other test files, that don't use TestRunner
import 'webcrypto/random_test.dart' as random_test;
import 'webcrypto/digest_test.dart' as digest_test;

/// Test runners from all test files except `digest_test.dart` and
/// `random_test.dart`, which do not use [TestRunner].
final testRunners = <TestRunner>[
  aescbc_test.runner,
  aesctr_test.runner,
  aesgcm_test.runner,
  ecdh_test.runner,
  ecdsa_test.runner,
  hkdf_test.runner,
  hmac_test.runner,
  pbkdf2_test.runner,
  rsaoaep_test.runner,
  rsapss_test.runner,
  rsassapkcs1v15_test.runner,
];

/// Utility function that runs all tests using [test].
///
/// This makes it easy to run tests from `flutter drive`, when testing on a
/// device.
void runAllTests({TestFn test = test}) {
  for (final r in testRunners) {
    r.runTests(test: test);
  }
  // We don't use [TestRunner] for all tests, so we just add them manually.
  random_test.runTests(test: test);
  digest_test.runTests(test: test);
}
