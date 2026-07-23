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
