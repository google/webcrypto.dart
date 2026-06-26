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

void spawnJniForDesktopTests() {
  if (Platform.isAndroid) {
    return;
  }

  final helperDir = Directory('build/jni_libs');
  final helperName = Platform.isWindows
      ? 'dartjni.dll'
      : Platform.isMacOS
      ? 'libdartjni.dylib'
      : 'libdartjni.so';
  // Keep regular non-JNI test runs usable; `dart run jni:setup` opts desktop
  // tests into the JNI helper needed by the android-jca exploration backend.
  if (!File.fromUri(helperDir.uri.resolve(helperName)).existsSync()) {
    return;
  }

  Jni.spawnIfNotExists(dylibDir: helperDir.path);
}
