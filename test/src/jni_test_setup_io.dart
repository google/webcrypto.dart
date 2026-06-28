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

import 'dart:io';

import 'package:jni/jni.dart';

const _desktopJniSetupMessage =
    'Run `dart run jni:setup` before running desktop JNI tests.';

String? get jniHelperSetupSkipReason {
  if (Platform.isAndroid) {
    return null;
  }

  return _desktopJniHelperFile.existsSync() ? null : _desktopJniSetupMessage;
}

void spawnJniForDesktopTests() {
  final setupError = jniHelperSetupSkipReason;
  if (setupError != null) {
    throw StateError(setupError);
  }

  if (Platform.isAndroid) {
    return;
  }

  Jni.spawnIfNotExists(dylibDir: _desktopJniHelperDir.path);
}

Directory get _desktopJniHelperDir => Directory('build/jni_libs');

File get _desktopJniHelperFile {
  final helperName = Platform.isWindows
      ? 'dartjni.dll'
      : Platform.isMacOS
      ? 'libdartjni.dylib'
      : 'libdartjni.so';
  return File.fromUri(_desktopJniHelperDir.uri.resolve(helperName));
}
