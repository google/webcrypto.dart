// Copyright 2026 Google LLC
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

final _buildDependencyExtensions = {
  '.S',
  '.asm',
  '.c',
  '.cc',
  '.cmake',
  '.cpp',
  '.h',
  '.inc',
};

const _buildDependencyFileNames = {'CMakeLists.txt'};

Iterable<Uri> buildDependencies(Uri packageRoot) sync* {
  yield* _filesForBuild(Directory.fromUri(packageRoot.resolve('src/')));
  yield* _filesForBuild(
    Directory.fromUri(packageRoot.resolve('third_party/boringssl/')),
  );
}

Iterable<Uri> _filesForBuild(Directory root) sync* {
  if (!root.existsSync()) {
    return;
  }

  for (final entity in root.listSync(recursive: true, followLinks: false)) {
    if (entity is! File) {
      continue;
    }
    if (!_buildDependencyFileNames.contains(entity.uri.pathSegments.last) &&
        !_buildDependencyExtensions.any(entity.uri.path.endsWith)) {
      continue;
    }
    yield entity.uri;
  }
}
