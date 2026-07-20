#!/usr/bin/env bash
# Copyright 2026 The webcrypto.dart authors.
# Licensed under the Apache License, Version 2.0.

# Artifact assertions shared by native-platform CI jobs. This intentionally
# inspects final app packages instead of accepting a successful compiler exit.
set -euo pipefail

fail() {
  echo "native-assets inspection failed: $*" >&2
  exit 1
}

platform="${1:-}"
artifact="${2:-}"
[[ -n "$platform" && -n "$artifact" ]] || {
  echo "usage: $0 <android|ios|macos|linux> <artifact>" >&2
  exit 64
}

case "$platform" in
  android)
    [[ -f "$artifact" ]] || fail "APK not found: $artifact"
    entries="$(unzip -Z1 "$artifact" | grep -E '^lib/[^/]+/libwebcrypto\.so$' || true)"
    [[ -n "$entries" ]] || fail 'APK has no libwebcrypto.so'
    while IFS= read -r entry; do
      abi="$(cut -d/ -f2 <<<"$entry")"
      count="$(grep -c "^lib/$abi/libwebcrypto\.so$" <<<"$entries")"
      [[ "$count" == 1 ]] || fail "APK has $count webcrypto libraries for $abi"
    done <<<"$entries"
    if unzip -Z1 "$artifact" | grep -Eq 'webcrypto_plugin|libwebcrypto_plugin'; then
      fail 'APK contains a legacy webcrypto plugin artifact'
    fi
    echo "$entries"
    ;;

  ios)
    app="$artifact"
    [[ -d "$app" ]] || fail "iOS app not found: $app"
    library="$(find "$app/Frameworks" -type f -path '*/webcrypto.framework/webcrypto' 2>/dev/null)"
    count="$(printf '%s\n' "$library" | sed '/^$/d' | wc -l | tr -d ' ')"
    [[ "$count" == 1 ]] || fail "expected one iOS webcrypto framework binary, found $count"
    file "$library" | grep -q 'arm64' || fail 'iOS webcrypto binary is not arm64'
    nm -gU "$library" | grep -q '_webcrypto_lookup_symbol$' || fail 'iOS lookup symbol is not exported'
    if find "$app" -iname '*webcrypto_plugin*' -print -quit | grep -q .; then
      fail 'iOS app contains legacy plugin output'
    fi
    file "$library"
    ;;

  macos)
    app="$artifact"
    [[ -d "$app" ]] || fail "macOS app not found: $app"
    library="$(find "$app/Contents/Frameworks" -type f -path '*/webcrypto.framework/Versions/A/webcrypto' 2>/dev/null)"
    count="$(printf '%s\n' "$library" | sed '/^$/d' | wc -l | tr -d ' ')"
    [[ "$count" == 1 ]] || fail "expected one macOS webcrypto framework binary, found $count"
    lipo -info "$library" | grep -q 'x86_64' || fail 'macOS webcrypto binary lacks x86_64'
    lipo -info "$library" | grep -q 'arm64' || fail 'macOS webcrypto binary lacks arm64'
    nm -gU "$library" | grep -q '_webcrypto_lookup_symbol$' || fail 'macOS lookup symbol is not exported'
    if find "$app" -iname '*webcrypto_plugin*' -print -quit | grep -q .; then
      fail 'macOS app contains legacy plugin output'
    fi
    file "$library"
    ;;

  linux)
    bundle="$artifact"
    [[ -d "$bundle" ]] || fail "Linux bundle not found: $bundle"
    library="$(find "$bundle" -type f -name libwebcrypto.so)"
    count="$(printf '%s\n' "$library" | sed '/^$/d' | wc -l | tr -d ' ')"
    [[ "$count" == 1 ]] || fail "expected one Linux webcrypto library, found $count"
    file "$library" | grep -q 'ELF 64-bit' || fail 'Linux webcrypto library is not 64-bit ELF'
    nm -D "$library" | grep -q ' webcrypto_lookup_symbol$' || fail 'Linux lookup symbol is not exported'
    if find "$bundle" -iname '*webcrypto_plugin*' -print -quit | grep -q .; then
      fail 'Linux bundle contains legacy plugin output'
    fi
    file "$library"
    ;;

  *)
    fail "unknown platform: $platform"
    ;;
esac
