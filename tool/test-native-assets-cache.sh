#!/usr/bin/env bash
# Copyright 2026 The webcrypto.dart authors.
# Licensed under the Apache License, Version 2.0.

# Black-box tests the expensive Native Assets cache. Two independent consumers
# race on a cold key, then a source mutation must produce a distinct cache key.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMP="$(mktemp -d)"
CACHE_HOME="$TEMP/home"
CACHE_ROOT="$CACHE_HOME/.cache/webcrypto.dart"
mkdir -p "$CACHE_HOME"
trap 'rm -rf "$TEMP"' EXIT

make_consumer() {
  local directory="$1"
  local webcrypto_path="$2"
  mkdir -p "$directory/test"
  cat >"$directory/pubspec.yaml" <<YAML
name: webcrypto_cache_consumer
environment:
  sdk: ^3.10.0
dependencies:
  webcrypto:
    path: $webcrypto_path
dev_dependencies:
  test: any
YAML
  cat >"$directory/test/cache_test.dart" <<'DART'
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webcrypto/webcrypto.dart';

void main() {
  test('native asset is usable', () {
    final bytes = Uint8List(32);
    fillRandomBytes(bytes);
    expect(bytes, isNot(everyElement(0)));
  });
}
DART
  (cd "$directory" && flutter pub get >/dev/null)
}

assert_cache_entries() {
  local expected="$1"
  local count
  count="$(find "$CACHE_ROOT" -maxdepth 2 -type f \
    \( -name libwebcrypto.so -o -name libwebcrypto.dylib -o -name webcrypto.dll \) \
    | wc -l | tr -d ' ')"
  [[ "$count" == "$expected" ]] || {
    echo "expected $expected webcrypto cache entries, found $count" >&2
    find "$CACHE_ROOT" -maxdepth 3 -print >&2 || true
    exit 1
  }
  if find "$CACHE_ROOT" -type f -name '*.tmp' -print -quit \
      | grep -q .; then
    echo 'cache contains a partially published temporary file' >&2
    exit 1
  fi
  while IFS= read -r library; do
    local expected_digest actual_digest
    expected_digest="$(tr -d '[:space:]' <"$library.sha256")"
    actual_digest="$(shasum -a 256 "$library" | awk '{print $1}')"
    [[ "$actual_digest" == "$expected_digest" ]] || {
      echo "cache digest mismatch: $library" >&2
      exit 1
    }
  done < <(find "$CACHE_ROOT" -maxdepth 2 -type f \
    \( -name libwebcrypto.so -o -name libwebcrypto.dylib -o -name webcrypto.dll \))
}

# Same source/toolchain/target, independent hook output directories, one cold
# shared cache key. The lock must serialize build/publication.
make_consumer "$TEMP/consumer-a" "$ROOT"
make_consumer "$TEMP/consumer-b" "$ROOT"
(
  cd "$TEMP/consumer-a"
  HOME="$CACHE_HOME" dart test >"$TEMP/consumer-a.log" 2>&1
) &
pid_a=$!
(
  cd "$TEMP/consumer-b"
  HOME="$CACHE_HOME" dart test >"$TEMP/consumer-b.log" 2>&1
) &
pid_b=$!
wait "$pid_a" || { cat "$TEMP/consumer-a.log" >&2; exit 1; }
wait "$pid_b" || { cat "$TEMP/consumer-b.log" >&2; exit 1; }
assert_cache_entries 1

# Identical package copy plus one native source change must not reuse the first
# key. Copy only publishable inputs, not generated build/cache output.
mkdir -p "$TEMP/webcrypto-mutated"
tar -C "$ROOT" \
  --exclude=.git --exclude=.dart_tool --exclude=build --exclude=example/build \
  -cf - . | tar -C "$TEMP/webcrypto-mutated" -xf -
printf '\n/* Native Assets cache invalidation test. */\n' \
  >>"$TEMP/webcrypto-mutated/src/webcrypto.c"
make_consumer "$TEMP/consumer-mutated" "$TEMP/webcrypto-mutated"
(
  cd "$TEMP/consumer-mutated"
  HOME="$CACHE_HOME" dart test >"$TEMP/consumer-mutated.log" 2>&1
) || { cat "$TEMP/consumer-mutated.log" >&2; exit 1; }
assert_cache_entries 2

echo 'Native Assets cache concurrency, integrity, and invalidation: PASS'
