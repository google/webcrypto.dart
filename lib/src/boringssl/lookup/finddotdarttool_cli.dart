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

import 'dart:cli' as cli;
import 'dart:isolate' show Isolate;
import 'dart:io' show File;
import 'finddotdarttool_fallback.dart' as fallback;

/// Find the `.dart_tool/` folder, returns `null` if unable to find it.
Uri findDotDartTool() {
  // Find [Isolate.packageConfig] and check if contains:
  //  * `package_config.json`, or,
  //  * `.dart_tool/package_config.json`.
  // If either is the case we know the path to `.dart_tool/`.
  final packageConfig = cli.waitFor(Isolate.packageConfig);
  if (packageConfig != null &&
      File.fromUri(packageConfig.resolve('package_config.json')).existsSync()) {
    return packageConfig.resolve('./');
  }
  if (packageConfig != null &&
      File.fromUri(packageConfig.resolve('.dart_tool/package_config.json'))
          .existsSync()) {
    return packageConfig.resolve('.dart_tool/');
  }

  // If [Isolate.packageConfig] isn't helpful we fallback to looking at the
  // current script location and traverse up from there.
  return fallback.findDotDartTool();
}
