# webcrypto_example

This application shows how to use `package:webcrypto` for computing a SHA-1
hash of user provided string.

Additionally, this example application provides integration tests for devices.

To run the Android JNI/JCA digest smoke test:

```sh
flutter test integration_test/jni_digest_test.dart \
  -d emulator-name
```

To run the Android JNI/JCA HMAC smoke test:

```sh
flutter test integration_test/jni_hmac_test.dart \
  -d emulator-name
```

To run the Android JNI/JCA HKDF smoke test:

```sh
flutter test integration_test/jni_hkdf_test.dart \
  -d emulator-name
```

To run the Android JNI/JCA PBKDF2 smoke test:

```sh
flutter test integration_test/jni_pbkdf2_test.dart \
  -d emulator-name
```

To benchmark PBKDF2 at realistic iteration counts on Android:

```sh
flutter test integration_test/jni_pbkdf2_benchmark.dart \
  -d emulator-name
```

To run the Android JNI/JCA AES-GCM smoke test:

```sh
flutter test integration_test/jni_aesgcm_test.dart \
  -d emulator-name
```

To run the Android JNI/JCA AES-CBC smoke test:

```sh
flutter test integration_test/jni_aescbc_test.dart \
  -d emulator-name
```

To run the Android JNI/JCA AES-CTR smoke test:

```sh
flutter test integration_test/jni_aesctr_test.dart \
  -d emulator-name
```

To run the Android JNI/JCA RSASSA-PKCS1-v1_5 smoke test:

```sh
flutter test integration_test/jni_rsassapkcs1v15_test.dart \
  -d emulator-name
```

To run the Android JNI/JCA RSA-OAEP smoke test:

```sh
flutter test integration_test/jni_rsaoaep_test.dart \
  -d emulator-name
```

To run the Android JNI/JCA RSA-PSS smoke test:

```sh
flutter test integration_test/jni_rsapss_test.dart \
  -d emulator-name
```

To run the Android JNI/JCA ECDSA smoke test:

```sh
flutter test integration_test/jni_ecdsa_test.dart \
  -d emulator-name
```

To run the Android JNI/JCA ECDH smoke test:

```sh
flutter test integration_test/jni_ecdh_test.dart \
  -d emulator-name
```
