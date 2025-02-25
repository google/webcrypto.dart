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
import requests

TOOL_PATH = os.path.dirname(os.path.realpath(__file__))
ROOT_PATH = os.path.dirname(TOOL_PATH)

BORINGSSL_REPOSITORY = 'https://boringssl.googlesource.com/boringssl'
BORINGSSL_REVISION = 'e056f59c7dfdcf891af03bc7900c946ac485c78f'


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


def mkdirp(path):
    """ Create a directory if it doesn't exist """
    if not os.path.exists(path):
        os.makedirs(path)


def git_clone(target):
    """ Clone BoringSSL into target/src """
    src = os.path.join(target, 'src')
    subprocess.check_call(['git', 'clone', BORINGSSL_REPOSITORY, src])


def git_checkout(target):
    """ Checkout the specific BoringSSL revision """
    src = os.path.join(target, 'src')
    subprocess.check_call(['git', 'checkout', BORINGSSL_REVISION], cwd=src)


def copy_boringssl(target):
    """ Copy BoringSSL files to the appropriate directories """
    src = os.path.join(target, 'src')
    dest = os.path.join(ROOT_PATH, 'third_party', 'boringssl')
    shutil.copytree(src, dest, dirs_exist_ok=True)


def bump_revision(new_revision):
    """ Update the BORINGSSL_REVISION in this script """
    script_path = os.path.realpath(__file__)
    with open(script_path, 'r') as file:
        lines = file.readlines()
    
    with open(script_path, 'w') as file:
        for line in lines:
            if line.startswith('BORINGSSL_REVISION'):
                file.write(f'BORINGSSL_REVISION = \'{new_revision}\'\n')
            else:
                file.write(line)




import json
def get_latest_revision():
    """ Fetch the latest commit hash from the BoringSSL repository """
    response = requests.get(f'{BORINGSSL_REPOSITORY}/+log/master?format=JSON')
    print(f"Response status code: {response.status_code}")
    #print(f"Response text: {response.text}")

    if response.status_code == 200:
        # Check if response text is empty
        if not response.text:
            raise Exception("Response is empty.")
        
        # Remove the first chars : )]}'
        json_text = response.text[5:]

        # Check if the response is valid JSON
        try:
            data = json.loads(json_text)
        except Exception as e:
            print(f"Error processing JSON: {e}")
            raise Exception("Response is not valid JSON.")

        if 'log' not in data:
            raise Exception("JSON response does not contain the 'log' key.")
        if not isinstance(data['log'], list):
            raise Exception("'log' is not a list")

        if len(data['log']) == 0:
            raise Exception("'log' list is empty.")
        
        if 'commit' not in data['log'][0]:
            raise Exception("First element of 'log' does not contain the 'commit' key.")

        latest_commit = data['log'][0]['commit']
        return latest_commit
    else:
        raise Exception('Failed to fetch the latest revision')






def main():
    new_revision = get_latest_revision()
    bump_revision(new_revision)
    with tempfile.TemporaryDirectory() as tmpdir:
        cleanup()
        git_clone(tmpdir)
        git_checkout(tmpdir)
        copy_boringssl(tmpdir)


if __name__ == '__main__':
    main()
