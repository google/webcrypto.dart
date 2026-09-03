#!/bin/bash

# Copyright 2026 Google LLC
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

set -euo pipefail

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    cat <<'EOF'
Usage: ./tool/update-chromium-test-vectors.sh [revision]

Vendors Chromium WebCrypto test vectors at the given Git revision. If no
revision is supplied, Chromium's current HEAD revision is used.
EOF
    exit 0
fi

if [[ $# -gt 1 ]]; then
    echo "Usage: $0 [revision]" >&2
    exit 1
fi

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
ROOT="$DIR/.."
TARGET="$ROOT/third_party/chromium"
CHROMIUM_REPOSITORY='https://chromium.googlesource.com/chromium/src'
REVISION="${1:-}"
TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TEMP_DIR"' EXIT

if [[ -z "$REVISION" ]]; then
    REVISION="$(git ls-remote "$CHROMIUM_REPOSITORY" HEAD | awk '{print $1}')"
fi

if [[ ! "$REVISION" =~ ^[0-9a-f]{40}$ ]]; then
    echo "Unable to resolve a 40-character Chromium revision." >&2
    exit 1
fi

for command in curl python3; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "$command is required to vendor Chromium test vectors." >&2
        exit 1
    fi
done

download() {
    local source_path="$1"
    local destination="$2"
    local url="$CHROMIUM_REPOSITORY/+/$REVISION/$source_path?format=TEXT"

    curl --fail --location --silent --show-error "$url" |
        python3 -c 'import base64, sys; sys.stdout.buffer.write(base64.b64decode(sys.stdin.buffer.read()))' \
        > "$destination"
}

download 'LICENSE' "$TEMP_DIR/LICENSE"
download \
    'components/test/data/webcrypto/bad_ec_keys.json' \
    "$TEMP_DIR/bad_ec_keys.json"

mkdir -p "$TARGET"
mv "$TEMP_DIR/LICENSE" "$TARGET/LICENSE"
mv "$TEMP_DIR/bad_ec_keys.json" "$TARGET/bad_ec_keys.json"
printf '%s\n' "$REVISION" > "$TARGET/REVISION"

echo "Vendored Chromium WebCrypto test vectors at revision $REVISION."
