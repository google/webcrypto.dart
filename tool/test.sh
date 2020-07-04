#!/bin/bash -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

cd "$DIR/.."
flutter pub get

flutter test
flutter test --platform chrome

cd "$DIR/../example"
flutter drive --target test_driver/webcrypto_tester.dart

# We can problem skip vm and chrome, but afaik this is the only way to test on
# Firefox.
cd "$DIR/.."
xvfb-run flutter pub run test -p vm,chrome,firefox

echo '### All tests passed'
