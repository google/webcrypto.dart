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

import 'package:flutter_driver/flutter_driver.dart';
import 'package:test/test.dart';
import 'dart:convert' show json;

Future<void> main() async {
  final driver = await FlutterDriver.connect();

  // Utility to send request to webcrypto_tester application
  Future<Map<String, dynamic>> send(
    String command, [
    Map<String, dynamic> options = const {},
  ]) async {
    return json.decode(await driver
        .requestData(json.encode({'command': command, ...options})));
  }

  // List all test cases
  final testNames = (await send('list-tests'))['tests'] as List;

  // Declare all test cases
  for (var i = 0; i < testNames.length; i++) {
    test(testNames[i], () async {
      final response = await send('run-test', {'index': i});
      final error = response['error'] as String;
      final logLines = response['logLines'] as List;
      logLines.forEach(print);
      if (error != null) {
        throw Exception(
          'Test failed with: $error\n'
          'See: log for original stacktrace',
        );
      }
    });
  }

  tearDownAll(() => driver?.close());
}
