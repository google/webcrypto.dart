#!/usr/bin/env python3
"""Check that the Android library exports every symbol used by Dart FFI."""

import pathlib
import re
import subprocess
import sys


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: check_android_exports.py LLVM_NM LIBWEBCRYPTO_SO", file=sys.stderr)
        return 2

    root = pathlib.Path(__file__).resolve().parent.parent
    bindings = root / "lib" / "src"
    required = set()
    for path in bindings.rglob("generated_bindings.dart"):
        source = path.read_text()
        required.update(re.findall(r"symbol: ['\"]([^'\"]+)['\"]", source))
        required.update(
            re.findall(
                r"@ffi\.Native<[^;]+?>\(\)\s*external\s+[^\n;]+\s+(\w+)\s*\(",
                source,
                re.DOTALL,
            )
        )

    if not required:
        print("No FFI symbols found in generated bindings", file=sys.stderr)
        return 1

    output = subprocess.check_output(
        [sys.argv[1], "-D", "--defined-only", sys.argv[2]], text=True
    )
    exported = {line.split()[-1] for line in output.splitlines() if line.strip()}
    missing = sorted(required - exported)
    if missing:
        print("Missing Android FFI exports:\n" + "\n".join(missing), file=sys.stderr)
        return 1

    unexpected = sorted(exported - required)
    if unexpected:
        print(
            f"Unexpected Android exports ({len(unexpected)}):\n"
            + "\n".join(unexpected[:20]),
            file=sys.stderr,
        )
        return 1

    print(f"Verified {len(required)} Android FFI exports")
    return 0


if __name__ == "__main__":
    sys.exit(main())
