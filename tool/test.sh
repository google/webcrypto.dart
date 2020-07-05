#!/bin/bash -e

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


DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

cd "$DIR/.."
flutter pub get
flutter pub run webcrypto:setup

flutter test
flutter test --platform chrome

cd "$DIR/../example"
flutter drive --target test_driver/webcrypto_tester.dart

# We can problem skip vm and chrome, but afaik this is the only way to test on
# Firefox (xvfb-run, is necessary for Firefox testing to work)
cd "$DIR/.."
xvfb-run flutter pub run test -p vm,chrome,firefox

echo '### All tests passed'
