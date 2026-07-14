# JCA JNI Bindings

These bindings are generated with JNIgen for the Android JCA backend
exploration.

To regenerate them, run from the package root:

```sh
bash tool/update-jca-bindings.sh
```

Requirements:

- Flutter SDK
- Java Development Kit (JDK) 17 (`java -version` must resolve to JDK 17)
- Android SDK Platform 36 installed and discoverable by Android tooling
  (`ANDROID_SDK_ROOT` can be set explicitly if needed)

The known reproducible generation environment uses JDK 17. The JNIgen config
is pinned to Android API 36 so the checked-in generated bindings are
reproducible across machines. Use JDK 17 and Android SDK Platform 36 for
regeneration rather than substituting newer locally installed versions.

The generated output is:

```text
lib/src/third_party/jca/generated_bindings.dart
```
