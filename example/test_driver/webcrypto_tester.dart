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

import 'dart:async';
import 'dart:convert' show json;
import 'package:flutter/widgets.dart';
import 'package:flutter/material.dart';
import 'package:flutter_driver/driver_extension.dart';
import '../../test/testrunners.dart';

void main() {
  final testNames = <String>[];
  final testCallbacks = <FutureOr<void> Function()>[];

  runAllTests(test: (name, callback) {
    testNames.add(name);
    testCallbacks.add(callback);
  });

  enableFlutterDriverExtension(handler: (String data) async {
    final request = json.decode(data) as Map<String, dynamic>;
    final response = <String, dynamic>{};
    final command = request['command'] as String;

    if (command == 'list-tests') {
      response['tests'] = testNames;
    }
    if (command == 'run-test') {
      final fn = testCallbacks[request['index']];
      String error;
      final logLines = [];
      await runZonedGuarded(fn, (e, st) {
        error ??= e.toString();
        logLines.add('Uncaught error in test: $e\nStackTrace: $st');
      }, zoneSpecification: ZoneSpecification(print: (
        self,
        parent,
        zone,
        line,
      ) {
        logLines.add(line);
      }));
      response['error'] = error;
      response['logLines'] = logLines;
    }

    return json.encode(response);
  });

  runApp(MaterialApp(home: Text('Running webcrypto tests')));
}
