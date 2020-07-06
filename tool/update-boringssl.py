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
BORINGSSL_PATH = os.path.join(ROOT_PATH, 'third_party', 'boringssl')

BORINGSSL_REPOSITORY = 'https://boringssl.googlesource.com/boringssl'
BORINGSSL_REVISION = '33f8d33af0dcb083610e978baad5a8b6e1cfee82'


def cleanup():
    """ Remove boringssl sources and generated files """
    if os.path.exists(BORINGSSL_PATH):
        shutil.rmtree(BORINGSSL_PATH)
    mkdirp(BORINGSSL_PATH)


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
]


def generate(target):
    # Change directory into target because generate_build_files expects to run
    # from this location
    os.chdir(target)

    # Import src/util/generate_build_files.py
    sys.path.append(os.path.join(target, 'src', 'util'))
    import generate_build_files

    gen = SourcesCMakeGenerator()
    generate_build_files.EMBED_TEST_DATA = False
    generate_build_files.main([gen])

    # Write third_party/boringssl/sources.cmake
    with open(os.path.join(BORINGSSL_PATH, 'sources.cmake'), 'w') as f:
        f.write(gen.sources_cmake)

    # Copy over all used files
    files_to_copy = gen.files_used + FILES_TO_RETAIN
    for f in sorted(set(files_to_copy)):
        src = os.path.join(target, f)
        dst = os.path.join(BORINGSSL_PATH, f)
        mkdirp(os.path.dirname(dst))
        shutil.copy(src, dst)


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


class SourcesCMakeGenerator(object):
    """
        Generator for generate_build_files which holds contents for
        sources.cmake and list of files to be used, when done.
    """

    def __init__(self):
        self.sources_cmake = SOURCES_CMAKE_HEADER
        self.files_used = []

    def define(self, variable, files):
        """ Define variable in sources.cmake to hold files """
        self.files_used += files
        self.sources_cmake += '\nset(' + variable + '\n'
        self.sources_cmake += '\n'.join((
            '  ${BORINGSSL_ROOT}' + f for f in sorted(files)
        ))
        self.sources_cmake += '\n)\n'

    def WriteFiles(self, file_sets, asm_outputs):
        """
            Implement WriteFiles as will be called by generate_build_files.

            file_sets is a dict mapping from targets to list of files, and,
            asm_outputs is a list of nested tuples on the form:
                ((os, arch), list_of_files)
            for each operating system and architecture.

            All file paths are relative to target (current working directory)
        """
        # Retain public headers
        self.files_used += file_sets['crypto_headers']

        # Retain internal headers (otherwise, we can't build)
        self.files_used += file_sets['crypto_internal_headers']

        # Retain fips_fragments (otherwise, we can't build)
        self.files_used += file_sets['fips_fragments']

        # Define and retain sources for libcrypto.so
        self.define('crypto_sources', file_sets['crypto'])

        # Define and sources various ASM files used by libcrypto.so
        for ((osname, arch), asm_files) in asm_outputs:
            self.define('crypto_sources_%s_%s' % (osname, arch), asm_files)


def mkdirp(path):
    if not os.path.isdir(path):
        os.makedirs(path)


def main():
    try:
        print('Updating third_party/boringssl/')
        tmp = tempfile.mkdtemp(prefix='roll-boring-')
        cleanup()
        git_clone(tmp)
        generate(tmp)
        print('Updated to BoringSSL revision: ' + BORINGSSL_REVISION)
    finally:
        shutil.rmtree(tmp)


if __name__ == '__main__':
    sys.exit(main())
