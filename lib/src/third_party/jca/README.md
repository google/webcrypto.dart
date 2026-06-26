# JCA JNI Bindings

These bindings are generated with JNIgen for the Android JCA backend
exploration.

To regenerate them, run from the package root:

```sh
tool/update-jca-bindings.sh
```

Requirements:

- Flutter SDK
- Android SDK Platform 36 installed and discoverable by Android tooling
  (`ANDROID_SDK_ROOT` can be set explicitly if needed)

The JNIgen config is pinned to Android API 36 so the checked-in generated
bindings are reproducible across machines. Do not change the API level locally
to match an installed SDK; install Android SDK Platform 36 instead.

The generated output is:

```text
lib/src/third_party/jca/generated_bindings.dart
```
