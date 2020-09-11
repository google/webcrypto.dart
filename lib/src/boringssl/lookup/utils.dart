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

import 'dart:io' show Platform, Directory, File;
import 'dart:ffi';
import 'symbols.generated.dart';

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
Pointer<Void> Function(Sym) lookupLibraryInDotDartTool() {
  final dotDartTool = _findDotDartTool();
  if (dotDartTool == null) {
    return null;
  }

  final libraryFile = File.fromUri(
    dotDartTool.resolve('webcrypto/$libraryFileName'),
  );
  if (libraryFile.existsSync()) {
    final library = DynamicLibrary.open(libraryFile.path);

    // Try to lookup the 'webcrypto_lookup_symbol' symbol
    // ignore: non_constant_identifier_names
    final webcrypto_lookup_symbol = library
        .lookup<NativeFunction<Pointer<Void> Function(Int32)>>(
          'webcrypto_lookup_symbol',
        )
        .asFunction<Pointer<Void> Function(int)>();

    // Return a function from Sym to lookup using `webcrypto_lookup_symbol`
    return (Sym s) => webcrypto_lookup_symbol(s.index);
  }
  return null;
}

/// Find the `.dart_tool/` folder, returns `null` if unable to find it.
Uri _findDotDartTool() {
  // HACK: Because 'dart:isolate' is unavailable in Flutter we have no means
  //       by which we can find the location of the package_config.json file.
  //       Which we need, because the binary library created by:
  //         flutter pub run webcrypto:setup
  //       is located relative to this path. As a workaround we use
  //       `Platform.script` and traverse level-up until we find a
  //       `.dart_tool/package_config.json` file.

  // Find script directory
  Uri root;
  if (Platform.script.isScheme('data')) {
    // If `Platform.script` is a data: [Uri] then we are being called from
    // `package:test`, luckily this means that CWD is project root.
    root = Directory.current.uri;
  } else {
    root = Platform.script.resolve('./');
  }

  // Traverse up until we see a `.dart_tool/package_config.json` file.
  do {
    if (File.fromUri(root.resolve('.dart_tool/package_config.json'))
        .existsSync()) {
      return root.resolve('.dart_tool/');
    }
  } while (root != (root = root.resolve('..')));
  return null;
}
