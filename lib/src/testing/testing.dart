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

// TestRunner implementations
import 'webcrypto/aescbc.dart' as aescbc;
import 'webcrypto/aesctr.dart' as aesctr;
import 'webcrypto/aesgcm.dart' as aesgcm;
import 'webcrypto/ecdh.dart' as ecdh;
import 'webcrypto/ecdsa.dart' as ecdsa;
import 'webcrypto/hkdf.dart' as hkdf;
import 'webcrypto/hmac.dart' as hmac;
import 'webcrypto/pbkdf2.dart' as pbkdf2;
import 'webcrypto/rsaoaep.dart' as rsaoaep;
import 'webcrypto/rsapss.dart' as rsapss;
import 'webcrypto/rsassapkcs1v15.dart' as rsassapkcs1v15;

// Other test files, that don't use TestRunner
import 'webcrypto/random.dart' as random;
import 'webcrypto/digest.dart' as digest;

/// Test runners from all test files except `digest.dart` and
/// `random.dart`, which do not use [TestRunner].
final _testRunners = <TestRunner>[
  aescbc.runner,
  aesctr.runner,
  aesgcm.runner,
  ecdh.runner,
  ecdsa.runner,
  hkdf.runner,
  hmac.runner,
  pbkdf2.runner,
  rsaoaep.runner,
  rsapss.runner,
  rsassapkcs1v15.runner,
];

/// Utility function that runs all tests using [test].
///
/// This makes it easy to run tests from `flutter drive`, when testing on a
/// device.
void runAllTests(TestFn test) {
  for (final r in _testRunners) {
    r.runTests(test: test);
  }
  // We don't use [TestRunner] for all tests, so we just add them manually.
  random.runTests(test: test);
  digest.runTests(test: test);
}
