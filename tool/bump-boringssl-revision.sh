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

    python3 - "$src_root" > "$manifest" <<'PY'
import json
import os
import sys


class Capture:
    def WriteFiles(self, file_sets, asm_outputs):
        self.file_sets = file_sets
        self.asm_outputs = asm_outputs


boringssl_root = os.path.abspath(sys.argv[1])
sys.path.insert(0, os.path.join(boringssl_root, "util"))
import generate_build_files  # type: ignore

capture = Capture()
cwd = os.getcwd()
try:
    os.chdir(boringssl_root)
    generate_build_files.EMBED_TEST_DATA = False
    generate_build_files.main([capture])
finally:
    os.chdir(cwd)

payload = {
    "crypto_sources": sorted(capture.file_sets["crypto"]),
    "crypto_headers": sorted(capture.file_sets["crypto_headers"]),
    "crypto_internal_headers": sorted(capture.file_sets["crypto_internal_headers"]),
    "fips_fragments": sorted(capture.file_sets["fips_fragments"]),
    "asm_outputs": {
        f"{osname}_{arch}": sorted(files)
        for (osname, arch), files in capture.asm_outputs
    },
}
json.dump(payload, sys.stdout, indent=2, sort_keys=True)
sys.stdout.write("\n")
PY
}

prefix_src_tree_path() {
    local path="$1"
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
    jq -r '.crypto_sources[]' "$manifest" | while read -r file; do
        echo "  \${BORINGSSL_ROOT}$(prefix_src_tree_path "$file")" >> "$dest"
    done
    echo ")" >> "$dest"

    jq -r '.asm_outputs | keys[]' "$manifest" | while read -r key; do
        echo "" >> "$dest"
        echo "set(crypto_sources_$key" >> "$dest"
        jq -r --arg key "$key" '.asm_outputs[$key][]' "$manifest" | while read -r file; do
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

    jq -r "$jq_selector" "$manifest" | while read -r file; do
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

    jq -r '.asm_outputs[]?[]' "$manifest" | while read -r file; do
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

    log_info "Enumerating source files using upstream generate_build_files.py"
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
    check_command python3 "python3 is required to enumerate BoringSSL source files"

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

    section "Generating symbols table"
    log_info "Running generate_symbols_table.dart..."
    dart run "$DIR/generate_symbols_table.dart"

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
