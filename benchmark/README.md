# PBKDF2 benchmark

The PBKDF2 benchmark measures SHA-256 derivation of a 256-bit output at 1,000,
10,000, and 100,000 iterations. It uses password and salt values containing
bytes above `0x7f`, and the desktop benchmark verifies that JNI and FFI produce
the same output before collecting timings.

Set up desktop JNI and run the desktop JNI/FFI comparison from the package
root:

```sh
dart run jni:setup
dart run benchmark/impl_jni_pbkdf2_benchmark.dart
```

Run the JNI benchmark on Android from the example application:

```sh
cd example/webcrypto_demo_flutter_app
flutter test integration_test/jni_pbkdf2_benchmark.dart -d emulator-name
```

Results are medians after warm-up. They measure the complete backend call,
including isolate and JNI overhead, and are not suitable for comparing
different devices without controlling their runtime and thermal state.
