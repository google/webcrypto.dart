#!/bin/bash

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

set -e

# Script to update BoringSSL revision and regenerate all necessary files
# Usage: ./tool/bump-boringssl-revision.sh [revision] [--dry-run]

# Show help if requested
if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    echo "Usage: $0 [revision] [--dry-run]"
    echo ""
    echo "Updates BoringSSL to the specified revision or latest if no revision provided."
    echo ""
    echo "Arguments:"
    echo "  revision    Optional. Specific BoringSSL revision (SHA) to update to."
    echo "              If not provided, uses the latest revision from the repository."
    echo "  --dry-run   Optional. Check if update is needed without performing the update."
    echo ""
    echo "Examples:"
    echo "  $0                                    # Update to latest revision"
    echo "  $0 78b48c1f2a973ff0a4ed18b9618d533101bd4144  # Update to specific revision"
    echo "  $0 --dry-run                          # Check if update is needed"
    echo ""
    exit 0
fi

# Check for dry-run mode
DRY_RUN=false
TARGET_REVISION=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        -*)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
        *)
            if [ -z "$TARGET_REVISION" ]; then
                TARGET_REVISION="$1"
            else
                echo "Multiple revisions specified. Use --help for usage information"
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

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
}

section() {
    echo ""
    echo "### $1"
    echo ""
}

# Function to get current revision from REVISION file
get_current_revision() {
    if [ -f "$REVISION_FILE" ]; then
        cat "$REVISION_FILE" | tr -d ' \t\n\r'
    else
        log_error "REVISION file not found at $REVISION_FILE"
        exit 1
    fi
}

# Function to update revision in REVISION file
update_revision() {
    local new_revision="$1"
    echo "$new_revision" > "$REVISION_FILE"
    log_success "Updated REVISION file to: $new_revision"
}

# Function to get latest revision from BoringSSL repository
get_latest_revision() {
    git ls-remote "$BORINGSSL_REPOSITORY" HEAD | awk '{print $1}'
}

# Function to check if git is available
check_git() {
    if ! command -v git &> /dev/null; then
        log_error "git is not installed or not in PATH"
        exit 1
    fi
}

# Function to create directories
mkdirp() {
    local path="$1"
    if [ ! -d "$path" ]; then
        mkdir -p "$path"
    fi
}

# Function to cleanup old BoringSSL files
cleanup_boringssl() {
    log_info "Cleaning up old BoringSSL files..."
    for sub in 'third_party/boringssl' 'darwin/third_party/boringssl'; do
        local p="$ROOT/$sub"
        if [ -d "$p" ]; then
            rm -rf "$p"
        fi
        mkdirp "$p"
    done
}

# Function to clone BoringSSL at specific revision
git_clone_boringssl() {
    local revision="$1"
    local temp_dir="$2"
    local target="$temp_dir/src"
    
    mkdirp "$target"
    log_info "Cloning BoringSSL repository..." >&2
    git clone "$BORINGSSL_REPOSITORY" "$target" > /dev/null 2>&1
    log_info "Checking out revision: $revision" >&2
    git -C "$target" checkout --detach "$revision" > /dev/null 2>&1
    echo "$target"
}

# Function to write sources.cmake
write_sources_cmake() {
    local sources="$1"
    local asms="$2"
    local dest="$ROOT/third_party/boringssl/sources.cmake"
    
    log_info "Writing sources.cmake..."
    
    cat > "$dest" << 'EOF'
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

# **GENERATED FILE DO NOT MODIFY**
#
# This file is generated using:
# `tool/bump-boringssl-revision.sh`
EOF

    # Add crypto_sources
    echo "" >> "$dest"
    echo "set(crypto_sources" >> "$dest"
    echo "$sources" | while read -r file; do
        echo "  \${BORINGSSL_ROOT}$file" >> "$dest"
    done
    echo ")" >> "$dest"
    
    # Add crypto_asm_sources
    echo "" >> "$dest"
    echo "set(crypto_asm_sources" >> "$dest"
    echo "$asms" | while read -r file; do
        echo "  \${BORINGSSL_ROOT}$file" >> "$dest"
    done
    echo ")" >> "$dest"
}

# Function to copy sources
copy_sources() {
    local sources="$1"
    local internal_hdrs="$2"
    local asms="$3"
    local src_root="$4"
    local dest_root="$ROOT/third_party/boringssl"
    
    log_info "Copying BoringSSL sources..."
    
    # 1) public headers
    log_info "Copying public headers..."
    cp -r "$src_root/include" "$dest_root/"
    
    # 2) all .cc sources
    log_info "Copying source files..."
    echo "$sources" | while read -r file; do
        if [ -n "$file" ]; then
            local src="$src_root/$file"
            local dst="$dest_root/$file"
            mkdirp "$(dirname "$dst")"
            cp "$src" "$dst"
        fi
    done
    
    # 3) internal headers
    log_info "Copying internal headers..."
    echo "$internal_hdrs" | while read -r file; do
        if [ -n "$file" ]; then
            local src="$src_root/$file"
            local dst="$dest_root/$file"
            mkdirp "$(dirname "$dst")"
            cp "$src" "$dst"
        fi
    done
    
    # 4) ASM slices
    log_info "Copying ASM files..."
    echo "$asms" | while read -r file; do
        if [ -n "$file" ]; then
            local src="$src_root/$file"
            local dst="$dest_root/$file"
            mkdirp "$(dirname "$dst")"
            cp "$src" "$dst"
        fi
    done
    
    # 5) always-retain root files
    log_info "Copying root files..."
    for file in README.md LICENSE INCORPORATING.md; do
        if [ -f "$src_root/$file" ]; then
            cp "$src_root/$file" "$dest_root/"
        fi
    done
}

# Function to write fake darwin sources
write_fake_darwin() {
    local sources="$1"
    
    log_info "Creating fake Darwin sources..."
    
    echo "$sources" | while read -r file; do
        if [ -n "$file" ] && [[ "$file" == *.cc ]]; then
            local orig="$ROOT/third_party/boringssl/$file"
            local tgt="$ROOT/darwin/third_party/boringssl/$file"
            mkdirp "$(dirname "$tgt")"
            
            cat > "$tgt" << 'EOF'
/*
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
// `tool/bump-boringssl-revision.sh`
EOF
            # Calculate relative path using a simpler approach
            local rel_path="../../../../third_party/boringssl/$file"
            echo "#include \"$rel_path\"" >> "$tgt"
        fi
    done
}

# Function to write BoringSSL README
write_boringssl_readme() {
    local readme_dst="$ROOT/third_party/boringssl/README.md"
    
    cat > "$readme_dst" << 'EOF'
# Incorporation of BoringSSL in `package:webcrypto`

**GENERATED FOLDER DO NOT MODIFY**

This folder contains sources from BoringSSL allowing `package:webcrypto` to
incorporate libcrypto from BoringSSL. Contents of this folder is generated
using `tool/bump-boringssl-revision.sh` which utilizes scripts and procedures from
`src/INCORPORATING.md` to faciliate embedding of libcrypto from BoringSSL.

Files in this folder are subject to `LICENSE` from the BoringSSL project.

Notice that this folder does NOT contain all source files from the BoringSSL
project. Only source files required to build `package:webcrypto` have been
retained. This is essential to minimize package size. For additional source
files and information about BoringSSL refer to the [BoringSSL repository][1].

[1]: https://boringssl.googlesource.com/boringssl/
EOF
}

# Main BoringSSL update function
update_boringssl_sources() {
    local revision="$1"
    local temp_dir=$(mktemp -d)
    
    log_info "Starting BoringSSL update to revision: $revision"
    
    cleanup_boringssl
    
    local src_root=$(git_clone_boringssl "$revision" "$temp_dir")
    
    # Load and parse sources.json
    log_info "Loading gen/sources.json"
    local sources_json="$src_root/gen/sources.json"
    
    if [ ! -f "$sources_json" ]; then
        log_error "sources.json not found at $sources_json"
        rm -rf "$temp_dir"
        exit 1
    fi
    
    # Check if jq is available for proper JSON parsing
    if ! command -v jq &> /dev/null; then
        log_error "jq is required for parsing sources.json. Please install jq."
        rm -rf "$temp_dir"
        exit 1
    fi
    
    # Extract sources using jq (matching the Python script logic exactly)
    log_info "Parsing sources.json with jq..."
    
    # Extract crypto and bcm source files
    local crypto_sources=$(jq -r '.crypto.srcs[]?' "$sources_json" 2>/dev/null || echo "")
    local bcm_sources=$(jq -r '.bcm.srcs[]?' "$sources_json" 2>/dev/null || echo "")
    
    # Extract internal headers
    local crypto_internal_hdrs=$(jq -r '.crypto.internal_hdrs[]?' "$sources_json" 2>/dev/null || echo "")
    local bcm_internal_hdrs=$(jq -r '.bcm.internal_hdrs[]?' "$sources_json" 2>/dev/null || echo "")
    
    # Extract assembly files
    local crypto_asm=$(jq -r '.crypto.asm[]?' "$sources_json" 2>/dev/null || echo "")
    local bcm_asm=$(jq -r '.bcm.asm[]?' "$sources_json" 2>/dev/null || echo "")
    
    # Combine all sources and headers
    local all_sources=$(echo -e "$crypto_sources\n$bcm_sources" | grep -v '^$' | sort -u)
    local all_internal_hdrs=$(echo -e "$crypto_internal_hdrs\n$bcm_internal_hdrs" | grep -v '^$' | sort -u)
    local all_asm=$(echo -e "$crypto_asm\n$bcm_asm" | grep -v '^$' | sort -u)
    
    log_info "Found $(echo "$all_sources" | wc -l) source files, $(echo "$all_internal_hdrs" | wc -l) internal headers, and $(echo "$all_asm" | wc -l) assembly files"
    
    write_sources_cmake "$all_sources" "$all_asm"
    copy_sources "$all_sources" "$all_internal_hdrs" "$all_asm" "$src_root"
    write_fake_darwin "$all_sources"
    write_boringssl_readme
    
    rm -rf "$temp_dir"
    
    log_success "Updated to BoringSSL revision $revision"
}

# Main execution function
main() {
    local current_revision=$(get_current_revision)
    
    log_info "Current BoringSSL revision: $current_revision"
    
    # Determine target revision
    if [ -n "$TARGET_REVISION" ]; then
        log_info "Using specified revision: $TARGET_REVISION"
    else
        TARGET_REVISION=$(get_latest_revision)
        log_info "Using latest revision: $TARGET_REVISION"
    fi
    
    # Check if update is needed
    if [ "$current_revision" = "$TARGET_REVISION" ]; then
        log_info "Already at revision $TARGET_REVISION - verifying with git diff"
        # Don't abort - continue to verify the files are actually correct
        # Running the update will be a no-op if truly at the right revision
    else
        log_info "Update needed: $current_revision -> $TARGET_REVISION"
    fi
    
    # If dry-run mode, just report the status
    if [ "$DRY_RUN" = true ]; then
        log_info "DRY RUN: Would update from $current_revision to $TARGET_REVISION"
        return 0
    fi
    
    # Check prerequisites
    check_git
    
    # Step 1: Clean up build artifacts
    section "Cleaning up build artifacts"
    log_info "Running clean.sh..."
    bash "$DIR/clean.sh"
    
    # Step 2: Update BoringSSL sources
    section "Updating BoringSSL sources"
    update_boringssl_sources "$TARGET_REVISION"
    
    # Step 3: Update revision file
    update_revision "$TARGET_REVISION"
    
    # Step 4: Get Dart dependencies
    section "Getting Dart dependencies"
    log_info "Running 'dart pub get'..."
    cd "$ROOT"
    dart pub get
    
    # Step 5: Generate symbols table
    section "Generating symbols table"
    log_info "Running generate_symbols_table.dart..."
    dart run "$DIR/generate_symbols_table.dart"
    
    # Step 6: Update FFI bindings
    section "Updating FFI bindings"
    log_info "Running update-bindings.sh..."
    bash "$DIR/update-bindings.sh"
    
    # Step 7: Run tests
    section "Running tests"
    log_info "Running test.sh..."
    bash "$DIR/test.sh"
    
    log_success "BoringSSL update completed successfully!"
    log_info "Updated from $current_revision to $TARGET_REVISION"
}

# Run main function with all arguments
main "$@" 
