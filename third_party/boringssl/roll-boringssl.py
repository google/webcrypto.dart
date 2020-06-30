#!/usr/bin/env python2

# Roll BoringSSL into third_party/boringssl/src/
# Remember to bump BORINGSSL_REVISION.

import os
import os.path
import shutil
import subprocess
import sys
import tempfile
from fnmatch import fnmatch

# thirdparty/boringssl/
BORINGSSL_PATH = os.path.dirname(os.path.realpath(__file__))
# thirdparty/boringssl/src
BORINGSSL_SRC_PATH = os.path.join(BORINGSSL_PATH, 'src')

BORINGSSL_REPOSITORY = 'https://boringssl.googlesource.com/boringssl'
BORINGSSL_REVISION = '33f8d33af0dcb083610e978baad5a8b6e1cfee82'

GENERATED_FILE_PATTERNS = [
    'linux-*',
    'mac-*',
    'win-*',
    'ios-*',
    'android-sources.cmake',
    'err_data.c',
]


def cleanup():
    "Remove boringssl sources and generated files"
    if os.path.exists(BORINGSSL_SRC_PATH):
        shutil.rmtree(BORINGSSL_SRC_PATH)

    # Remove generated files
    for f in os.listdir(BORINGSSL_PATH):
        if any((fnmatch(f, p) for p in GENERATED_FILE_PATTERNS)):
            f = os.path.join(BORINGSSL_PATH, f)
            if os.path.isfile(f):
                os.remove(f)
            else:
                shutil.rmtree(f)


def git_clone():
    "Clone boringssl into BORINGSSL_SRC_PATH"
    tmp = tempfile.mkdtemp(prefix='roll-boring-')
    try:
        subprocess.check_call(
            ['git', 'clone', BORINGSSL_REPOSITORY, tmp],
        )
        subprocess.check_call(
            ['git', 'checkout', '--detach', BORINGSSL_REVISION],
            cwd=tmp,
        )
        shutil.copytree(tmp, BORINGSSL_SRC_PATH, ignore=shutil.ignore_patterns(
            '.gitignore',
            '.github',
            '.git',
        ))
    finally:
        shutil.rmtree(tmp)


def generate():
    # Import src/util/generate_build_files.py
    sys.path.append(os.path.join(BORINGSSL_SRC_PATH, 'util'))
    import generate_build_files

    generate_build_files.EMBED_TEST_DATA = False
    generate_build_files.main([
        generate_build_files.AndroidCMake(),
    ])


def main():
    cleanup()
    git_clone()
    generate()


if __name__ == '__main__':
    sys.exit(main())
