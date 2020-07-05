#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
ROOT="$DIR/.."

# Remove all the generated files
# Not removing .cxx/ and .gradle/ can cause problems when jumping between
# flutter versions.

cd "$ROOT"
flutter clean

cd "$ROOT/example/"
flutter clean

cd "$ROOT"
rm -rf android/.cxx/
rm -rf example/android/.gradle/
rm -f example/.packages

