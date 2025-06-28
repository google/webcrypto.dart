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
import sys
import json
import shutil
import tempfile
import subprocess

TOOL_PATH = os.path.dirname(os.path.realpath(__file__))
ROOT_PATH = os.path.dirname(TOOL_PATH)
BORINGSSL_REPOSITORY = 'https://boringssl.googlesource.com/boringssl'
BORINGSSL_REVISION = '78b48c1f2a973ff0a4ed18b9618d533101bd4144'

FILES_TO_RETAIN = [
    'README.md',
    'LICENSE',
    'INCORPORATING.md',
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



def mkdirp(path):
    if not os.path.isdir(path):
        os.makedirs(path)

def cleanup():
    for sub in ['third_party/boringssl', 'darwin/third_party/boringssl']:
        p = os.path.join(ROOT_PATH, sub)
        if os.path.exists(p):
            shutil.rmtree(p)
        mkdirp(p)

def git_clone(tmpdir):
    """Clone BoringSSL into tmpdir/src at the pinned revision."""
    target = os.path.join(tmpdir, 'src')
    mkdirp(target)
    subprocess.check_call(['git', 'clone', BORINGSSL_REPOSITORY, target])
    subprocess.check_call(
        ['git', 'checkout', '--detach', BORINGSSL_REVISION],
        cwd=target
    )
    return target

def load_sources_json(src_root):
    """Load the pre-generated gen/sources.json file."""
    path = os.path.join(src_root, 'gen', 'sources.json')
    with open(path, 'r') as f:
        return json.load(f)

def write_sources_cmake(sources, asms):
    """Emit third_party/boringssl/sources.cmake with two variables."""
    def define(var, files):
        out = f'\nset({var}\n'
        for f in sorted(files):
            out += f'  ${{BORINGSSL_ROOT}}{f}\n'
        out += ')\n'
        return out

    cm = SOURCES_CMAKE_HEADER
    cm += define('crypto_sources', sources)
    cm += define('crypto_asm_sources', asms)

    dest = os.path.join(ROOT_PATH, 'third_party', 'boringssl', 'sources.cmake')
    with open(dest, 'w') as f:
        f.write(cm)

def copy_sources(sources, internal_hdrs, asms, src_root):
    dest_root = os.path.join(ROOT_PATH, 'third_party', 'boringssl')

    # 1) public headers
    shutil.copytree(
        os.path.join(src_root, 'include'),
        os.path.join(dest_root, 'include')
    )

    # 2) all .cc sources
    for f in sources:
        src = os.path.join(src_root, f)
        dst = os.path.join(dest_root, f)
        mkdirp(os.path.dirname(dst))
        shutil.copy(src, dst)

    # 3) internal headers (e.g. fipsmodule/*.h)
    for h in internal_hdrs:
        src = os.path.join(src_root, h)
        dst = os.path.join(dest_root, h)
        mkdirp(os.path.dirname(dst))
        shutil.copy(src, dst)

    # 4) ASM slices
    for a in asms:
        src = os.path.join(src_root, a)
        dst = os.path.join(dest_root, a)
        mkdirp(os.path.dirname(dst))
        shutil.copy(src, dst)

    # 5) always-retain root files
    for f in FILES_TO_RETAIN:
        src = os.path.join(src_root, f)
        dst = os.path.join(dest_root, f)
        shutil.copy(src, dst)

def write_fake_darwin(sources):
    """Under darwin/, create tiny wrappers that #include the real .cc files."""
    for f in sources:
        if not f.endswith('.cc'):
            continue
        orig = os.path.join(ROOT_PATH, 'third_party', 'boringssl', f)
        tgt  = os.path.join(ROOT_PATH, 'darwin', 'third_party', 'boringssl', f)
        mkdirp(os.path.dirname(tgt))
        contents = FAKE_DARWIN_SOURCE_HEADER
        rel = os.path.relpath(orig, os.path.dirname(tgt))
        with open(tgt, 'w') as w:
            w.write(contents)
            w.write(f'#include "{rel}"\n')

def main():
    if shutil.which('git') is None:
        print('Error: git not on PATH', file=sys.stderr)
        sys.exit(1)

    tmp = tempfile.mkdtemp(prefix='update-boringssl-')
    try:
        print('Cleaning up old boringssl/')
        cleanup()

        print('Cloning BoringSSL @', BORINGSSL_REVISION)
        src_root = git_clone(tmp)

        print('Loading gen/sources.json')
        data = load_sources_json(src_root)

        crypto = data['crypto']['srcs']
        bcm    = data['bcm']['srcs']

        # internal headers for build
        crypto_int = data['crypto'].get('internal_hdrs', [])
        bcm_int    = data['bcm'].get('internal_hdrs', [])
        internal_hdrs = crypto_int + bcm_int

        # ASM slices
        crypto_asm = data['crypto'].get('asm', [])
        bcm_asm    = data['bcm'].get('asm', [])
        asms = crypto_asm + bcm_asm

        sources = crypto + bcm

        print(f'Writing {len(sources)} .cc files, '
              f'{len(internal_hdrs)} internal headers, and '
              f'{len(asms)} ASM entries')

        write_sources_cmake(sources, asms)
        copy_sources(sources, internal_hdrs, asms, src_root)
        write_fake_darwin(sources)

        # top-level README
        readme_dst = os.path.join(ROOT_PATH, 'third_party', 'boringssl', 'README.md')
        with open(readme_dst, 'w') as f:
            f.write(BORINGSSL_FOLDER_README)

        print('✅ Updated to BoringSSL revision', BORINGSSL_REVISION)

    finally:
        shutil.rmtree(tmp, ignore_errors=True)

if __name__ == '__main__':
    main()
