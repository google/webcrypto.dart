#!/usr/bin/env python3

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

# Roll BoringSSL into third_party/boringssl/
# Remember to bump BORINGSSL_REVISION.

import os
import os.path
import shutil
import subprocess
import sys
import tempfile

TOOL_PATH = os.path.dirname(os.path.realpath(__file__))
ROOT_PATH = os.path.dirname(TOOL_PATH)

BORINGSSL_REPOSITORY = 'https://boringssl.googlesource.com/boringssl'
BORINGSSL_REVISION = 'a6d321b11fa80496b7c8ae6405468c212d4f5c87'


def cleanup():
    """ Remove boringssl sources and generated files """
    paths = [
        os.path.join(ROOT_PATH, 'third_party', 'boringssl'),
        os.path.join(ROOT_PATH, 'darwin', 'third_party', 'boringssl')
    ]
    for p in paths:
        if os.path.exists(p):
            shutil.rmtree(p)
        mkdirp(p)


def git_clone(target):
    """ Clone BoringSSL into target/src """
    src = os.path.join(target, 'src')
    mkdirp(src)
    subprocess.check_call(
        ['git', 'clone', BORINGSSL_REPOSITORY, src],
    )
    subprocess.check_call(
        ['git', 'checkout', '--detach', BORINGSSL_REVISION],
        cwd=src,
    )


# Files from BoringSSL that should always be retained
FILES_TO_RETAIN = [
    'src/README.md',
    'src/LICENSE',
    'src/INCORPORATING.md',
]

BORINGSSL_FOLDER_README = """# Incorporation of BoringSSL in `package:webcrypto`

**GENERATED FOLDER DO NOT MODIFY**

This folder contains sources from BoringSSL allowing `package:webcrypto` to
incorporate libcrypto from BoringSSL. Contents of this folder is generated
using `tool/update-boringssl.py` which utilizes scripts and procedures from
`src/INCORPORATING.md` to faciliate embedding of libcrypto from BoringSSL.

Files in this folder are subject to `LICENSE` from the BoringSSL project.

Notice that this folder does NOT contain all source files from the BoringSSL
project. Only source files required to build `package:webcrypto` have been
retained. This is essential to minimize package size. For additional source
files and information about BoringSSL refer to the [BoringSSL repository][1].

[1]: https://boringssl.googlesource.com/boringssl/
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
# `tool/update-boringssl.py`
"""

FAKE_DARWIN_SOURCE_HEADER = """/*
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
// `tool/update-boringssl.py`
"""


class BoringSSLGenerator(object):
    """
        Generator for src/util/generate_build_files.py from BoringSSL.

        This simply stores the variables, so we easily access them in function.
    """

    def WriteFiles(self, file_sets, asm_outputs):
        """
            WriteFiles will be called by generate_build_files.main(..)

            Parameters
            ----------
            file_sets : dict
                A dict mapping from targets to list of files.
            asm_outputs : list
                A list of nested tuples on the form:
                    ((os, arch), list_of_files)
                for each operating system and architecture.

            All file paths are relative to root the BoringSSL repository.
        """
        self.file_sets = file_sets
        self.asm_outputs = asm_outputs


def writeFile(path_relative_root, contents):
    with open(os.path.join(ROOT_PATH, path_relative_root), 'w') as f:
        f.write(contents)


def writeSourcesCmake(g):
    """
        Write third_party/boringssl/sources.cmake
    """
    def define(variable, files):
        """ Define variable in sources.cmake to hold files """
        s = ''
        s += '\nset(' + variable + '\n'
        s += '\n'.join((
            '  ${BORINGSSL_ROOT}' + f for f in sorted(files)
        ))
        s += '\n)\n'
        return s

    # Define sources for libcrypto
    sources_cmake = ''
    sources_cmake += SOURCES_CMAKE_HEADER
    sources_cmake += define('crypto_sources', g.file_sets['crypto'])

    # Define and sources various ASM files used by libcrypto
    for ((osname, arch), asm_files) in g.asm_outputs:
        name = 'crypto_sources_%s_%s' % (osname, arch)
        sources_cmake += define(name, asm_files)

    # Write third_party/boringssl/sources.cmake
    p = os.path.join('third_party', 'boringssl', 'sources.cmake')
    writeFile(p, sources_cmake)


def copySourceFiles(g, boringssl_clone):
    """
        Copy source files into third_party/boringssl/
    """
    files_to_copy = []
    # Copy libcrypto sources
    files_to_copy += g.file_sets['crypto']
    # Copy public headers
    files_to_copy += g.file_sets['crypto_headers']
    # Copy internal headers (otherwise, we can't build)
    files_to_copy += g.file_sets['crypto_internal_headers']
    # Copy fips_fragments (otherwise, we can't build)
    files_to_copy += g.file_sets['fips_fragments']
    # Copy various ASM files used by libcrypto
    for ((osname, arch), asm_files) in g.asm_outputs:
        files_to_copy += asm_files
    # Copy static files
    files_to_copy += FILES_TO_RETAIN

    for f in sorted(set(files_to_copy)):
        src = os.path.join(boringssl_clone, f)
        dst = os.path.join(ROOT_PATH, 'third_party', 'boringssl', f)
        mkdirp(os.path.dirname(dst))
        shutil.copy(src, dst)


def writeFakeDarwinSource(g):
    """
        Write fake-source files that each #include "../..." the original source
        file for darwin/
    """
    for f in sorted(set(g.file_sets['crypto'])):
        target = os.path.join(ROOT_PATH, 'darwin', 'third_party', 'boringssl', f)
        original = os.path.join(ROOT_PATH, 'third_party', 'boringssl', f)
        rel = os.path.relpath(original, os.path.dirname(target))
        mkdirp(os.path.dirname(target))
        contents = ''
        contents += FAKE_DARWIN_SOURCE_HEADER
        contents += '\n'
        contents += '#include "'+rel+'"\n'
        writeFile(os.path.join('darwin', 'third_party', 'boringssl', f), contents)


def generate(boringssl_clone):
    # Change directory into boringssl_clone because generate_build_files.py
    # expects to run from this location
    os.chdir(boringssl_clone)

    # Import src/util/generate_build_files.py
    sys.path.append(os.path.join(boringssl_clone, 'src', 'util'))
    import generate_build_files

    g = BoringSSLGenerator()
    generate_build_files.EMBED_TEST_DATA = False
    generate_build_files.main([g])

    # Write third_party/boringssl/sources.cmake
    writeSourcesCmake(g)

    # Copy source files into third_party/boringssl/
    copySourceFiles(g, boringssl_clone)

    # Write fake-source files for darwin/ which use #include "../..." to include
    # the original source file. This is necessary because webcrypto.podspec
    # cannot reference sources not under the darwin/ folder.
    # But the C-preprocessor can still include them :D
    writeFakeDarwinSource(g)

    # Add a README.md to the third_party/boringssl/ folder
    readmePath = os.path.join('third_party', 'boringssl', 'README.md')
    writeFile(readmePath, BORINGSSL_FOLDER_README)

    # Copy LICENSE file for BoringSSL into third_party/boringssl/LICENSE
    # because all files in this folder are copied or generated from BoringSSL.
    LICENSE_src = os.path.join(boringssl_clone, 'src', 'LICENSE')
    LICENSE_dst = os.path.join(
        ROOT_PATH, 'third_party', 'boringssl', 'LICENSE')
    shutil.copy(LICENSE_src, LICENSE_dst)


def mkdirp(path):
    if not os.path.isdir(path):
        os.makedirs(path)


def main():
    if shutil.which('go') is None:
        print('Could not find "go" on $PATH')
        return 1
    if shutil.which('git') is None:
        print('Could not find "git" on $PATH')
        return 1
    if shutil.which('perl') is None:
        print('Could not find "perl" on $PATH')
        return 1
    try:
        print('Updating third_party/boringssl/')
        tmp = tempfile.mkdtemp(prefix='update-boringssl-')
        cleanup()
        git_clone(tmp)
        generate(tmp)
        print('Updated to BoringSSL revision: ' + BORINGSSL_REVISION)
        return 0
    finally:
        shutil.rmtree(tmp)
        return 1


if __name__ == '__main__':
    sys.exit(main())
