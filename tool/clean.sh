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

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
ROOT="$DIR/.."

# Remove all the generated files
# Not removing .cxx/ and .gradle/ can cause problems when jumping between
# flutter versions.

cd "$ROOT"
flutter clean

cd "$ROOT/example/"
flutter clean

cd "$ROOT"
rm -rf android/.cxx/
rm -rf example/android/.gradle/
rm -f example/.packages

