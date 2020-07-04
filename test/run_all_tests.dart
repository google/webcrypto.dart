import 'utils.dart';
import 'package:test/test.dart' show test;
import 'testrunners.dart' show testRunners;

/// Utility function that runs all tests using [test].
///
/// This makes it easy to run tests from `flutter drive`, when testing on a
/// device.
void runAllTests({TestFn test = test}) {
  for (final r in testRunners) {
    r.runTests(test: test);
  }
}
