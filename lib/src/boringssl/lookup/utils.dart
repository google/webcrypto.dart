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

import 'symbols.generated.dart';
import '../bindings/generated_bindings.dart';

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

/// Look for the webcrypto binary library in the `.dart_tool/webcrypto/` folder,
/// and initialize it with [initialize_dart_dl].
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

    // Try to lookup the 'webcrypto_lookup_symbol' symbol.
    final webcryptoDartDL = WebCryptoDartDL(library);
    final webcrypto_lookup_symbol = webcryptoDartDL.webcrypto_lookup_symbol;

    // Return a function from Sym to lookup using `webcrypto_lookup_symbol`
    Pointer<T> lookup<T extends NativeType>(String s) =>
        webcrypto_lookup_symbol(symFromString(s).index).cast<T>();

    // Initialize library
    initialize_dart_dl(lookup);

    return lookup;
  }
  return null;
}

/// Initialize library for use with Dart dynamic linking, by calling
/// `webcrypto_dart_dl_initialize`.
///
/// This must be called before we start using the library.
void initialize_dart_dl(
    Pointer<T> Function<T extends NativeType>(String) lookup) {
  final webcrypto_dart_dl_initialize =
      WebCryptoDartDL.fromLookup(lookup).webcrypto_dart_dl_initialize;

  if (webcrypto_dart_dl_initialize(NativeApi.initializeApiDLData) != 1) {
    throw UnsupportedError(
      'package:webcrypto does not work with this version of the Dart DL API.'
      'Please update to a newer version of package:webcrypto. And ensure that'
      'you have rebuilt the current version with '
      '`flutter pub run webcrypt:setup` if running locally.',
    );
  }
}

/// Find the `.dart_tool/` folder, returns `null` if unable to find it.
Uri? _findDotDartTool() {
  // HACK: We have no good mechanism for finding the library created by:
  //         flutter pub run webcrypto:setup
  //       So we search relative to the script path and CWD.

  // Find script directory
  Uri root = Platform.script.resolve('./');

  // Traverse up until we see a `.dart_tool/package_config.json` file.
  do {
    if (File.fromUri(root.resolve('.dart_tool/package_config.json'))
        .existsSync()) {
      return root.resolve('.dart_tool/');
    }
  } while (root != (root = root.resolve('..')));

  // If traversing from script directory didn't work, we can look starting from
  // CWD, this typically happens if running as test.
  root = Directory.current.uri;

  // Traverse up until we see a `.dart_tool/package_config.json` file.
  do {
    if (File.fromUri(root.resolve('.dart_tool/package_config.json'))
        .existsSync()) {
      return root.resolve('.dart_tool/');
    }
  } while (root != (root = root.resolve('..')));

  return null;
}
