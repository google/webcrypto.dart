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

# Script to update BoringSSL revision and regenerate all necessary files.
# Usage: ./tool/bump-boringssl-revision.sh [revision] [--dry-run]

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    cat <<'EOF'
Usage: ./tool/bump-boringssl-revision.sh [revision] [--dry-run]

Updates BoringSSL to the specified revision or latest if no revision is given.

Arguments:
  revision    Optional. Specific BoringSSL revision (SHA) to update to.
  --dry-run   Optional. Report the target revision without changing files.
EOF
    exit 0
fi

DRY_RUN=false
TARGET_REVISION=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        -*)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
        *)
            if [[ -z "$TARGET_REVISION" ]]; then
                TARGET_REVISION="$1"
            else
                echo "Multiple revisions specified" >&2
                exit 1
            fi
            shift
            ;;
    esac
done

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
ROOT="$DIR/.."
REVISION_FILE="$DIR/REVISION"
BORINGSSL_REPOSITORY='https://boringssl.googlesource.com/boringssl'
PYTHON_BIN=""

log_info() {
    echo "[info] $1"
}

log_success() {
    echo "[ok] $1"
}

log_error() {
    echo "[error] $1" >&2
}

section() {
    echo ""
    echo "### $1"
    echo ""
}

get_current_revision() {
    if [[ -f "$REVISION_FILE" ]]; then
        tr -d ' \t\n\r' < "$REVISION_FILE"
    else
        log_error "REVISION file not found at $REVISION_FILE"
        exit 1
    fi
}

# update_revision <new-revision>
update_revision() {
    local new_revision="$1"
    echo "$new_revision" > "$REVISION_FILE"
    log_success "Updated REVISION file to: $new_revision"
}

get_latest_revision() {
    git ls-remote "$BORINGSSL_REPOSITORY" HEAD | awk '{print $1}'
}

# check_command <command> <hint>
check_command() {
    local command="$1"
    local hint="$2"
    if ! command -v "$command" >/dev/null 2>&1; then
        log_error "$hint"
        exit 1
    fi
}

# resolve_python
resolve_python() {
    local command
    for command in python3 python; do
        if command -v "$command" >/dev/null 2>&1 &&
           "$command" -c "import sys" >/dev/null 2>&1; then
            echo "$command"
            return 0
        fi
    done

    log_error "python3 or python is required to enumerate BoringSSL source files"
    exit 1
}

cleanup_boringssl() {
    local path="$ROOT/third_party/boringssl"
    log_info "Cleaning up old BoringSSL files..."
    rm -rf "$path"
    mkdir -p "$path"
}

# git_clone_boringssl <revision> <destination-folder>
git_clone_boringssl() {
    local revision="$1"
    local target="$2"

    log_info "Cloning BoringSSL repository..."
    git clone "$BORINGSSL_REPOSITORY" "$target" >/dev/null 2>&1
    log_info "Checking out revision: $revision"
    git -C "$target" checkout --detach "$revision" >/dev/null 2>&1
}

# write_build_manifest <boringssl-src-root> <manifest-path>
write_build_manifest() {
    local src_root="$1"
    local manifest="$2"

    "$PYTHON_BIN" - "$src_root" > "$manifest" <<'PY'
import json
import os
import sys

boringssl_root = os.path.abspath(sys.argv[1])
sources_json = os.path.join(boringssl_root, "gen", "sources.json")
if not os.path.exists(sources_json):
    sources_json = os.path.join(boringssl_root, "sources.json")

if not os.path.exists(sources_json):
    raise SystemExit(f"Could not find sources.json in {boringssl_root}")

with open(sources_json, encoding="utf-8") as f:
    sources = json.load(f)

bcm = sources.get("bcm", {})
crypto = sources.get("crypto", {})
test_support = sources.get("test_support", {})


def classify_asm(path):
    normalized = path[4:] if path.startswith("src/") else path

    if normalized.endswith(".asm"):
        if "-x86-win.asm" in normalized or "586-win.asm" in normalized:
            return "win_x86"
        return "win_x86_64"

    if normalized.endswith("-win.S"):
        return "win_aarch64"

    if normalized.endswith("-apple.S"):
        if "armv7" in normalized or "armv4" in normalized:
            return "apple_arm"
        if "armv8" in normalized:
            return "apple_aarch64"
        if "-x86-" in normalized or "x86-apple" in normalized:
            return "apple_x86"
        return "apple_x86_64"

    if normalized.endswith("-linux.S"):
        if "ppc" in normalized:
            return "linux_ppc64le"
        if "armv7" in normalized or "armv4" in normalized:
            return "linux_arm"
        if "armv8" in normalized:
            return "linux_aarch64"
        if "-x86-" in normalized or "586-linux" in normalized:
            return "linux_x86"
        return "linux_x86_64"

    if normalized == "crypto/curve25519/asm/x25519-asm-arm.S":
        return "linux_arm"
    if normalized == "crypto/poly1305/poly1305_arm_asm.S":
        return "linux_arm"
    if normalized == "crypto/hrss/asm/poly_rq_mul.S":
        return "linux_x86_64"
    if normalized.startswith("third_party/fiat/asm/"):
        return "linux_x86_64"

    return None


asm_outputs = {
    "apple_aarch64": [],
    "apple_arm": [],
    "apple_x86": [],
    "apple_x86_64": [],
    "linux_aarch64": [],
    "linux_arm": [],
    "linux_ppc64le": [],
    "linux_x86": [],
    "linux_x86_64": [],
    "win_aarch64": [],
    "win_x86": [],
    "win_x86_64": [],
}

for file in (
    bcm.get("asm", [])
    + bcm.get("nasm", [])
    + crypto.get("asm", [])
    + crypto.get("nasm", [])
    + test_support.get("asm", [])
    + test_support.get("nasm", [])
):
    key = classify_asm(file)
    if key is not None:
        asm_outputs[key].append(file)

payload = {
    "crypto_sources": sorted(bcm.get("srcs", []) + crypto.get("srcs", [])),
    "crypto_headers": sorted(crypto.get("hdrs", [])),
    "crypto_internal_headers": sorted(
        bcm.get("internal_hdrs", [])
        + crypto.get("internal_hdrs", [])
    ),
    "fips_fragments": [],
    "asm_outputs": {key: sorted(files) for key, files in asm_outputs.items() if files},
}
json.dump(payload, sys.stdout, indent=2, sort_keys=True)
sys.stdout.write("\n")
PY
}

prefix_src_tree_path() {
    local path="$1"
    if [[ "$path" == src/* ]]; then
        echo "$path"
        return
    fi
    if [[ "$path" == */* ]]; then
        echo "src/$path"
    else
        echo "$path"
    fi
}

# write_sources_cmake <manifest-path>
write_sources_cmake() {
    local manifest="$1"
    local dest="$ROOT/third_party/boringssl/sources.cmake"

    log_info "Writing sources.cmake..."

    cat > "$dest" <<'EOF'
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

# **GENERATED FILE DO NOT MODIFY**
#
# This file is generated using:
# `tool/bump-boringssl-revision.sh`
EOF

    echo "" >> "$dest"
    echo "set(crypto_sources" >> "$dest"
    jq -r '.crypto_sources[]' "$manifest" | tr -d '\r' | while read -r file; do
        echo "  \${BORINGSSL_ROOT}$(prefix_src_tree_path "$file")" >> "$dest"
    done
    echo ")" >> "$dest"

    jq -r '.asm_outputs | keys[]' "$manifest" | tr -d '\r' | while read -r key; do
        echo "" >> "$dest"
        echo "set(crypto_sources_$key" >> "$dest"
        jq -r --arg key "$key" '.asm_outputs[$key][]' "$manifest" | tr -d '\r' | while read -r file; do
            echo "  \${BORINGSSL_ROOT}$file" >> "$dest"
        done
        echo ")" >> "$dest"
    done
}

# copy_manifest_group <manifest-path> <jq-selector> <source-root> <destination-root>
copy_manifest_group() {
    local manifest="$1"
    local jq_selector="$2"
    local src_root="$3"
    local dest_root="$4"

    jq -r "$jq_selector" "$manifest" | tr -d '\r' | while read -r file; do
        if [[ -n "$file" ]]; then
            local src="$src_root/$file"
            local dst="$dest_root/$(prefix_src_tree_path "$file")"
            mkdir -p "$(dirname "$dst")"
            cp "$src" "$dst"
        fi
    done
}

# copy_asm_outputs <manifest-path> <source-root> <destination-root>
copy_asm_outputs() {
    local manifest="$1"
    local src_root="$2"
    local dest_root="$3"

    jq -r '.asm_outputs[]?[]' "$manifest" | tr -d '\r' | while read -r file; do
        if [[ -n "$file" ]]; then
            local src="$src_root/$file"
            local dst="$dest_root/$file"
            mkdir -p "$(dirname "$dst")"
            cp "$src" "$dst"
        fi
    done
}

# copy_sources <manifest-path> <source-root>
copy_sources() {
    local manifest="$1"
    local src_root="$2"
    local dest_root="$ROOT/third_party/boringssl"

    log_info "Copying BoringSSL sources..."
    copy_manifest_group "$manifest" '.crypto_headers[]' "$src_root" "$dest_root"
    copy_manifest_group "$manifest" '.crypto_sources[]' "$src_root" "$dest_root"
    copy_manifest_group "$manifest" '.crypto_internal_headers[]' "$src_root" "$dest_root"
    copy_manifest_group "$manifest" '.fips_fragments[]' "$src_root" "$dest_root"
    copy_asm_outputs "$manifest" "$src_root" "$dest_root"

    log_info "Copying root files..."
    for file in README.md LICENSE INCORPORATING.md; do
        if [[ -f "$src_root/$file" ]]; then
            cp "$src_root/$file" "$dest_root/"
        fi
    done
}

write_boringssl_readme() {
    local readme_dst="$ROOT/third_party/boringssl/README.md"

    cat > "$readme_dst" <<'EOF'
# Incorporation of BoringSSL in `package:webcrypto`

**GENERATED FOLDER DO NOT MODIFY**

This folder contains sources from BoringSSL allowing `package:webcrypto` to
incorporate libcrypto from BoringSSL. Contents of this folder are generated
using `tool/bump-boringssl-revision.sh`.

Files in this folder are subject to `LICENSE` from the BoringSSL project.

Notice that this folder does NOT contain all source files from the BoringSSL
project. Only source files required to build `package:webcrypto` have been
retained. This is essential to minimize package size. For additional source
files and information about BoringSSL refer to the [BoringSSL repository][1].

[1]: https://boringssl.googlesource.com/boringssl/
EOF
}

# update_boringssl_sources <revision>
update_boringssl_sources() {
    local revision="$1"
    local temp_dir
    temp_dir=$(mktemp -d)
    local src_root="$temp_dir/boringssl"
    local manifest="$temp_dir/build-files.json"

    log_info "Starting BoringSSL update to revision: $revision"

    cleanup_boringssl
    git_clone_boringssl "$revision" "$src_root"

    log_info "Enumerating source files using upstream sources.json"
    write_build_manifest "$src_root" "$manifest"

    local source_count
    source_count=$(jq '.crypto_sources | length' "$manifest")
    local internal_header_count
    internal_header_count=$(jq '(.crypto_internal_headers | length) + (.fips_fragments | length)' "$manifest")
    local asm_count
    asm_count=$(jq '[.asm_outputs[] | length] | add // 0' "$manifest")
    log_info "Found $source_count source files, $internal_header_count internal headers, and $asm_count assembly files"

    write_sources_cmake "$manifest"
    copy_sources "$manifest" "$src_root"
    write_boringssl_readme

    rm -rf "$temp_dir"
    log_success "Updated vendored BoringSSL sources"
}

main() {
    local current_revision
    current_revision=$(get_current_revision)
    log_info "Current BoringSSL revision: $current_revision"

    if [[ -n "$TARGET_REVISION" ]]; then
        log_info "Using specified revision: $TARGET_REVISION"
    else
        TARGET_REVISION=$(get_latest_revision)
        log_info "Using latest revision: $TARGET_REVISION"
    fi

    if [[ "$current_revision" == "$TARGET_REVISION" ]]; then
        log_info "Already at revision $TARGET_REVISION; regenerating files to verify the checkout matches the recorded revision"
    else
        log_info "Update needed: $current_revision -> $TARGET_REVISION"
    fi

    if [[ "$DRY_RUN" == true ]]; then
        log_info "DRY RUN: Would update from $current_revision to $TARGET_REVISION"
        return 0
    fi

    check_command git "git is not installed or not in PATH"
    check_command dart "dart is required to regenerate bindings and run tests"
    check_command jq "jq is required to parse generated BoringSSL source metadata"
    PYTHON_BIN=$(resolve_python)

    section "Cleaning up build artifacts"
    log_info "Running clean.sh..."
    bash "$DIR/clean.sh"

    section "Updating BoringSSL sources"
    update_boringssl_sources "$TARGET_REVISION"

    update_revision "$TARGET_REVISION"

    section "Getting Dart dependencies"
    log_info "Running 'dart pub get --no-example'..."
    cd "$ROOT"
    dart pub get --no-example

    section "Generating direct bindings"
    log_info "Running generate_direct_bindings.dart..."
    dart "$DIR/generate_direct_bindings.dart"

    section "Updating FFI bindings"
    log_info "Running update-bindings.sh..."
    bash "$DIR/update-bindings.sh"

    section "Running tests"
    log_info "Running test.sh..."
    bash "$DIR/test.sh"

    log_success "BoringSSL update completed successfully"
    log_info "Updated from $current_revision to $TARGET_REVISION"
}

main "$@"
