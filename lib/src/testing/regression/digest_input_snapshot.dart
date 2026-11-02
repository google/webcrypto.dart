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

import 'package:webcrypto/webcrypto.dart';

import '../utils/utils.dart';

void main() => tests().runTests();

List<({String name, Future<void> Function() test})> tests() => [
  (
    name: 'Hash.digestBytes snapshots input at invocation',
    test: () async {
      final data = [1, 2, 3];
      final expected = await Hash.sha256.digestBytes(data);

      final pending = Hash.sha256.digestBytes(data);
      data[0] = 9;

      check(
        equalBytes(await pending, expected),
        'digestBytes must not observe a later input mutation',
      );
    },
  ),
];
