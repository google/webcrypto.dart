# Prebuilt Native Assets

Published versions of `package:webcrypto` include trusted prebuilt native
libraries for the initial desktop target matrix:

```text
prebuilt/
  linux-x64/
    libwebcrypto.so
  macos-arm64/
    libwebcrypto.dylib
  macos-x64/
    libwebcrypto.dylib
  windows-x64/
    webcrypto.dll
```

The build hook uses a matching prebuilt library when one is available. Targets
without a packaged prebuilt continue to build the native library from source
with CMake.

The Linux artifact is built on Ubuntu 20.04 and must not require a glibc
version newer than 2.31. The macOS x64 artifact uses a 10.15 deployment target,
while the arm64 artifact uses 11.0, the first macOS release supporting Apple
Silicon. The publishing workflow verifies these compatibility baselines before
it assembles the package.

## Building From Source

Consumers and CI can bypass a packaged prebuilt explicitly:

```yaml
hooks:
  user_defines:
    webcrypto:
      build_from_source: true
```

## Publishing

The prebuilt libraries are not committed to the repository. The
`.github/workflows/publish.yml` workflow builds them from the tagged source,
validates the assembled package, and includes them in the package published to
pub.dev.

Manually dispatching the workflow builds and validates the same artifacts but
does not publish a package.
