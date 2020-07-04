import 'testrunner.dart' show TestRunner;

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
