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

// ignore_for_file: non_constant_identifier_names

import 'dart:io' show Platform, Directory, File;
import 'dart:ffi';

/// Get platform-dependent library filename for the binary webcrypto library.
String get libraryFileName {
  const libraryName = 'webcrypto';
  if (Platform.isWindows) {
    return '$libraryName.dll';
  }
  if (Platform.isLinux) {
    return 'lib$libraryName.so';
  }
  if (Platform.isMacOS) {
    return 'lib$libraryName.dylib';
  }
  throw UnsupportedError(
    'Platform ${Platform.operatingSystem} is unsupported or embed '
    'the binary webcrypto library for package:webcrypto',
  );
}

/// Look for the webcrypto binary library in the `.dart_tool/webcrypto/` folder.
///
/// Returns `null` if it could not be found.
Pointer<T> Function<T extends NativeType>(String symbolName)?
lookupLibraryInDotDartTool() {
  final dotDartTool = _findDotDartTool();
  if (dotDartTool == null) {
    return null;
  }

  final libraryFile = File.fromUri(
    dotDartTool.resolve('webcrypto/$libraryFileName'),
  );
  if (libraryFile.existsSync()) {
    final library = DynamicLibrary.open(libraryFile.path);
    return library.lookup;
  }
  return null;
}

/// Find the `.dart_tool/` folder, returns `null` if unable to find it.
Uri? _findDotDartTool() {
  // HACK: We have no good mechanism for finding the legacy
  // `.dart_tool/webcrypto/` output, so we search relative to the script path
  // and CWD.

  // Find script directory
  Uri root = Platform.script.resolve('./');

  // Traverse up until we see a `.dart_tool/package_config.json` file.
  do {
    if (File.fromUri(
      root.resolve('.dart_tool/package_config.json'),
    ).existsSync()) {
      return root.resolve('.dart_tool/');
    }
  } while (root != (root = root.resolve('..')));

  // If traversing from script directory didn't work, we can look starting from
  // CWD, this typically happens if running as test.
  root = Directory.current.uri;

  // Traverse up until we see a `.dart_tool/package_config.json` file.
  do {
    if (File.fromUri(
      root.resolve('.dart_tool/package_config.json'),
    ).existsSync()) {
      return root.resolve('.dart_tool/');
    }
  } while (root != (root = root.resolve('..')));

  return null;
}
