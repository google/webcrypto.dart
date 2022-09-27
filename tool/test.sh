#!/bin/bash

# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -e
section() { echo ''; echo "### $1"; echo '';}

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

cd "$DIR/.."

section 'Running "flutter pub get"'
flutter pub get


flutter pub run webcrypto:setup

section 'flutter test (local)'
flutter test


section 'flutter test (chrome)'
flutter test --platform chrome

cd "$DIR/../example"

# List devices and run integration tests on each device (if available)
# Skip "chrome" because it's not supported by integration test system.
DEVICE_IDS=$(flutter devices --machine | grep '"sdk"')
for DEVICE in linux android; do
  if echo "$DEVICE_IDS" | grep -i "$DEVICE" > /dev/null; then
    section "Running integration tests on $DEVICE"
    xvfb-run flutter test integration_test/webcrypto_test.dart -d "$DEVICE"
  else
    section "Skipping integration tests on $DEVICE (missing device)"
  fi
done

# We can't run integration tests on chrome without using `flutter drive`, see:
# https://docs.flutter.dev/cookbook/testing/integration/introduction#5b-web
section 'Running integration tests on chrome'
xvfb-run "$DIR/with-chromedriver.sh" flutter drive \
 --driver=test_driver/integration_test.dart \
 --target=integration_test/webcrypto_test.dart \
 -d chrome

# We can problem skip vm and chrome, but afaik this is the only way to test on
# Firefox (xvfb-run, is necessary for Firefox testing to work)
cd "$DIR/.."

section 'flutter pub run test (vm,chrome,firefox)'
xvfb-run flutter pub run test -p vm,chrome,firefox

echo '### All tests passed'
