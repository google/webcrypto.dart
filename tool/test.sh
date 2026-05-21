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

run_with_xvfb() {
  if command -v xvfb-run >/dev/null 2>&1; then
    xvfb-run "$@"
  else
    "$@"
  fi
}

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

cd "$DIR/.."

section 'Running "dart pub get --no-example"'
dart pub get --no-example

section 'dart test (vm,chrome,firefox)'
run_with_xvfb dart test -p vm,chrome,firefox

cd "$DIR/../example"

section 'Running "flutter pub get" in example/'
flutter pub get

# List devices and run integration tests on each device (if available)
# Skip "chrome" because it's not supported by integration test system.
DEVICE_IDS=$(flutter devices --machine | grep '"sdk"')
for DEVICE in linux android; do
  if echo "$DEVICE_IDS" | grep -i "$DEVICE" > /dev/null; then
    section "Running integration tests on $DEVICE"
    run_with_xvfb flutter test integration_test/webcrypto_test.dart -d "$DEVICE"
  else
    section "Skipping integration tests on $DEVICE (missing device)"
  fi
done

echo '### All tests passed'
