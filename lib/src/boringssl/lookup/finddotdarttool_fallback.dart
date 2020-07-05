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

import 'dart:io' show Platform, File;

/// Find the `.dart_tool/` folder, returns `null` if unable to find it.
Uri findDotDartTool() {
  // HACK: Because 'dart:isolate' is unavailable in Flutter we have no means
  //       by which we can find the location of the package_config.json file.
  //       Which we need, because the binary library created by:
  //         flutter pub run webcrypto:setup
  //       is located relative to this path. As a workaround we use
  //       `Platform.script` and traverse level-up until we find a
  //       `.dart_tool/package_config.json` file.

  // Find script directory
  var root = Platform.script.resolve('./');
  // Traverse up until we see a `.dart_tool/package_config.json` file.
  do {
    if (File.fromUri(root.resolve('.dart_tool/package_config.json'))
        .existsSync()) {
      return root.resolve('.dart_tool/');
    }
  } while (root != (root = root.resolve('..')));
  return null;
}
