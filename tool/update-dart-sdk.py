#!/usr/bin/env python2

# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Roll Dart-SDK into third_party/dart-sdk/
# Remember to bump DARTSDK_REVISION.

import os
import os.path
import shutil
import subprocess
import sys
import tempfile

TOOL_PATH = os.path.dirname(os.path.realpath(__file__))
ROOT_PATH = os.path.dirname(TOOL_PATH)

DARTSDK_REPOSITORY = 'https://dart.googlesource.com/sdk/'
DARTSDK_REVISION = '09481aa6ca60a12a5885db108aa5152cecb73fb1'


def cleanup():
    """ Remove dart-sdk sources and generated files """
    paths = [
        os.path.join(ROOT_PATH, 'third_party', 'dart-sdk'),
        os.path.join(ROOT_PATH, 'ios', 'third_party', 'dart-sdk')
    ]
    for p in paths:
        if os.path.exists(p):
            shutil.rmtree(p)
        mkdirp(p)


def git_clone(target):
    """ Clone dart-sdk into target """
    mkdirp(target)
    subprocess.check_call(
        ['git', 'clone', DARTSDK_REPOSITORY, target],
    )
    subprocess.check_call(
        ['git', 'checkout', '--detach', DARTSDK_REVISION],
        cwd=target,
    )


# Files from dart-sdk that should always be retained
FILES_TO_RETAIN = [
    'README.dart-sdk',
    'README.md',
    'LICENSE',
]

DARTSDK_FOLDER_README = """# Dynamic linking Dart SDK in `package:webcrypto`

**GENERATED FOLDER DO NOT MODIFY**

This folder contains sources from the Dart SDK allowing `package:webcrypto` to
dynamically link against native Dart APIs. Contents of this folder is generated
using `tool/update-dart-sdk.py` which clones the Dart SDK and copies over the
files required for dynamic linking.

Files in this folder are subject to `LICENSE` from the Dart SDK project.

Notice that this folder does NOT contain all source files from the Dart SDK
project. Only source files required to build `package:webcrypto` have been
retained. This is essential to minimize package size. For additional source
files and information about the Dart SDK refer to the [Dart SDK repository][1].

[1]: https://github.com/dart-lang/sdk
"""

SOURCES_CMAKE_HEADER = """# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# **GENERATED FILE DO NOT MODIFY**
#
# This file is generated using:
# `tool/update-dart-sdk.py`
"""

FAKE_IOS_SOURCE_HEADER = """/*
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// **GENERATED FILE DO NOT MODIFY**
//
// This file is generated using:
// `tool/update-dart-sdk.py`
"""


def writeFile(path_relative_root, contents):
    with open(os.path.join(ROOT_PATH, path_relative_root), 'w') as f:
        f.write(contents)


def writeFakeIosSource(g):
    """
        Write fake-source files that each #include "../..." the original source
        file for ios/
    """
    for f in sorted(set(g.file_sets['crypto'])):
        target = os.path.join(ROOT_PATH, 'ios', 'third_party', 'boringssl', f)
        original = os.path.join(ROOT_PATH, 'third_party', 'boringssl', f)
        rel = os.path.relpath(original, os.path.dirname(target))
        mkdirp(os.path.dirname(target))
        contents = ''
        contents += FAKE_IOS_SOURCE_HEADER
        contents += '\n'
        contents += '#include "'+rel+'"\n'
        writeFile(os.path.join('ios', 'third_party', 'boringssl', f), contents)


def generate(dartsdk_clone):
    # Add a README.md to the third_party/dart-sdk/ folder
    readmePath = os.path.join('third_party', 'dart-sdk', 'README.md')
    writeFile(readmePath, DARTSDK_FOLDER_README)

    # Copy runtime/include/ into third_party/dart-sdk/src/runtime/include/
    mkdirp(os.path.join(ROOT_PATH, 'third_party', 'dart-sdk', 'src'))
    shutil.copytree(
        os.path.join(dartsdk_clone, 'runtime', 'include'),
        os.path.join(ROOT_PATH, 'third_party', 'dart-sdk',
                     'src', 'runtime', 'include'),
    )

    # Copy over files to retain
    for f in FILES_TO_RETAIN:
        shutil.copy(
            os.path.join(dartsdk_clone, f),
            os.path.join(ROOT_PATH, 'third_party', 'dart-sdk', 'src', f),
        )

    # Source files that should compiled
    source_files = [
        os.path.join('src', 'runtime', 'include', 'dart_api_dl.c'),
    ]

    # Write fake-source files for ios/ which use #include "../..." to include
    # the original source file. This is necessary because webcrypto.podspec
    # cannot reference sources not under the ios/ folder.
    # But the C-preprocessor can still include them :D
    for f in source_files:
        target = os.path.join(ROOT_PATH, 'ios', 'third_party', 'dart-sdk', f)
        original = os.path.join(ROOT_PATH, 'third_party', 'dart-sdk', f)
        rel = os.path.relpath(original, os.path.dirname(target))
        mkdirp(os.path.dirname(target))
        contents = ''
        contents += FAKE_IOS_SOURCE_HEADER
        contents += '\n'
        contents += '#include "'+rel+'"\n'
        writeFile(os.path.join('ios', 'third_party', 'dart-sdk', f), contents)

    # Write sources.cmake in third_party/dart-sdk/
    cmake_sources = ''
    cmake_sources += SOURCES_CMAKE_HEADER
    cmake_sources += '\nset(dart_dl_sources\n'
    cmake_sources += '\n'.join((
        '  ${DARTSDK_ROOT}' + f for f in sorted(source_files)
    ))
    cmake_sources += '\n)\n'
    writeFile(
        os.path.join('third_party', 'dart-sdk', 'sources.cmake'),
        cmake_sources,
    )

    # Copy LICENSE file for Dart SDK into third_party/dart-sdk/LICENSE
    # because all files in this folder are copied or generated from Dart SDK.
    LICENSE_src = os.path.join(dartsdk_clone, 'LICENSE')
    LICENSE_dst = os.path.join(
        ROOT_PATH, 'third_party', 'dart-sdk', 'LICENSE')
    shutil.copy(LICENSE_src, LICENSE_dst)


def mkdirp(path):
    if not os.path.isdir(path):
        os.makedirs(path)


def main():
    try:
        print('Updating third_party/dart-sdk/')
        tmp = tempfile.mkdtemp(prefix='update-dart-sdk-')
        cleanup()
        git_clone(tmp)
        generate(tmp)
        print('Updated to dart_lang/sdk revision: ' + DARTSDK_REVISION)
    finally:
        shutil.rmtree(tmp)


if __name__ == '__main__':
    sys.exit(main())
