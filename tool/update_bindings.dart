// Copyright 2021 Google LLC
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

void main(List<String> arguments) async {
  final root =
      Directory.fromUri(Platform.script).parent.parent.uri.toFilePath();

  final generateWebCryptoDL = Process.run('dart', [
    'run',
    'ffigen',
    '--config=$root/lib/src/boringssl/bindings/ffigen.yaml',
  ]);

  final generateBoringSsl = Process.run('dart', [
    'run',
    'ffigen',
    '--config=$root/lib/src/third_party/boringssl/ffigen.yaml',
  ]);

  final result1 = await generateWebCryptoDL;
  print(result1.stdout);
  print(result1.stderr);
  final result2 = await generateBoringSsl;
  print(result2.stdout);
  print(result2.stderr);
}
