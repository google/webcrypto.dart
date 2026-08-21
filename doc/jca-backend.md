Android JCA Backend Exploration
===============================

This document records the status of the experimental Android JCA backend on
the `android-jca-branch`. It is not a supported backend-selection guide yet.

## Current status

The branch includes the master synchronization from [#373], the RSA-PSS
parameter-order fix from [#375], and the JNI JWK validation fix from [#376].
Other provider and compatibility work remains separate so each change can be
reviewed on its own.

The branch implements the following primitives through `package:jni` and the
Android Java Cryptography Architecture (JCA):

| Primitive | Current coverage | Notes |
| --- | --- | --- |
| Digest | Shared desktop tests and Android smoke test | SHA-1, SHA-256, SHA-384, SHA-512 |
| HMAC and random | Shared desktop tests and Android smoke test | JCA `Mac` and `SecureRandom` |
| AES-CBC and AES-CTR | Shared desktop tests and Android smoke tests | |
| AES-GCM | Shared desktop tests and Android smoke test | 32- and 64-bit tags depend on the provider |
| RSASSA-PKCS1-v1_5 and RSA-OAEP | Shared desktop tests and Android smoke tests | RSA private-key re-import is currently blocked on the tested API 24-26 images; see [#371] |
| RSA-PSS | Shared desktop tests and Android smoke test | API 36 passes after [#375] configures parameters after initialization; the same API 24-26 RSA import blocker prevents an end-to-end result |
| ECDSA and ECDH | Shared desktop tests and Android smoke tests | P-256, P-384, P-521 |
| HKDF | Shared desktop tests and Android smoke test | |
| PBKDF2 | Not merged | See [#357] and [#361] |

[#357]: https://github.com/google/webcrypto.dart/pull/357
[#361]: https://github.com/google/webcrypto.dart/issues/361
[#371]: https://github.com/google/webcrypto.dart/issues/371
[#372]: https://github.com/google/webcrypto.dart/issues/372
[#373]: https://github.com/google/webcrypto.dart/pull/373
[#375]: https://github.com/google/webcrypto.dart/pull/375
[#376]: https://github.com/google/webcrypto.dart/pull/376
[#377]: https://github.com/google/webcrypto.dart/pull/377
[#378]: https://github.com/google/webcrypto.dart/pull/378

## Provider compatibility

JCA behavior is determined by the provider installed on the device, not only
by this package or the Android API level. Providers can differ in algorithm
names, accepted parameter combinations, initialization behavior, and the Java
exceptions they report. It is not practical to test every provider an Android
application may install.

The results below are observations from named environments, not guarantees for
all JCA providers. A supported JCA backend should preserve the package's public
error categories where possible, document known capability gaps, and keep
provider-specific exception messages out of its public contract.

The full desktop TestRunner is wired to JNI in `test/webcrypto_test.dart`.
On the branch state documented here, it reports 1,354 passing tests and 88
failures. Forty-six failures are from the unimplemented PBKDF2 backend. The
other 42 exercise AES-GCM with 32- or 64-bit authentication tags, which the
desktop SunJCE provider rejects.

The same TestRunner is wired into the Android demo integration test. A complete
run on an Android 16 (API 36) x86_64 emulator with the change that landed in
[#375] reported 1,397 passing tests and 46 failures, all from the PBKDF2
implementation that has not merged. This is one emulator/provider result, not
a supported API/ABI matrix or a CI result.

Observed Android emulator results are kept separate from the support policy:

| API and ABI | Observed provider | AES-GCM shared vectors | RSA-PSS shared vectors |
| --- | --- | --- | --- |
| API 24, x86_64 | AndroidOpenSSL 1.0 | 81 passed | 22 passed / 344 failed; the JNI backend rejects the imported key wrapper before the PSS operation runs |
| API 25, x86_64 | AndroidOpenSSL 1.0 | Not repeated | Focused public test fails when the JNI backend rejects the same non-CRT key wrapper |
| API 26, x86_64 | AndroidOpenSSL 1.0 | Not repeated | Focused public test fails when the JNI backend rejects the same non-CRT key wrapper |
| API 36, x86_64 | AndroidOpenSSL 1.0 | Included in the complete run; passed | 366 passed after [#375] configures PSS parameters after initialization |

On all four tested images, the generic `RSASSA-PSS` name was unavailable and
the `SHA1withRSA/PSS`, `SHA256withRSA/PSS`, `SHA384withRSA/PSS`, and
`SHA512withRSA/PSS` aliases were available. That observation does not imply
that every AndroidOpenSSL or third-party provider has the same aliases.

## AES-GCM tag lengths

Web Crypto permits 32, 64, 96, 104, 112, 120, and 128-bit AES-GCM tags. The
JNI backend passes the requested value to `GCMParameterSpec`.

Desktop SunJCE rejects 32- and 64-bit tags. In that case, the backend returns
an `UnsupportedError` that includes the tag length. Android 16's tested
provider passed the shared 32- through 128-bit vectors. The focused Android
smoke test accepts either successful encrypt/decrypt or that explicit error
for 32- and 64-bit tags because support remains provider-dependent. The
96-128 bit lengths are required by the JNI tests.

The final backend policy for Web Crypto-valid parameters that a provider does
not implement is still open. Options include documenting provider-dependent
support, adding a fallback, or implementing the operation independently.

## RSA private keys on API 24-26

The current RSA import validation assumes that a provider-created private key
implements `RSAPrivateCrtKey`. The tested API 24 image generates an
`OpenSSLRSAPrivateCrtKey`, but importing that key's PKCS#8 encoding returns an
`OpenSSLRSAPrivateKey` that does not expose the CRT interface. Requesting an
`RSAPrivateCrtKeySpec` from `KeyFactory` returns only an
`RSAPrivateKeySpec`, so its CRT components are still unavailable.

The JNI backend rejects the same provider key shape on the tested API 25 and
API 26 images. API 36 imports the encoding as `OpenSSLRSAPrivateCrtKey` and
passes the shared RSA-PSS suite. This affects the shared RSA key layer, not
only RSA-PSS. The fix must preserve import-time key validation and private JWK
export; skipping the CRT check would weaken the package contract.

## RSA-PSS provider behavior

The current demo application inherits Flutter's minimum SDK 24, so this project has not tested API 21-22. The [Android `Signature` documentation] lists the hash-specific `SHAxxxwithRSA/PSS` aliases from API 23, while the generic `RSASSA-PSS` name remains provider-dependent on older releases. The backend first tries the generic name and then the hash-specific name, but this does not create support where the installed provider has neither. The tested API 24, 25, 26, and 36 AndroidOpenSSL images expose the hash-specific aliases, not the generic name. API 36 also requires PSS parameters to be configured after `initSign` or `initVerify`; the full TestRunner verifies externally generated non-default salt lengths with that ordering. API 24-26 cannot yet exercise the complete PSS path because of the separate RSA private-key import problem above.

## Why use JCA

The intended benefit is to use Android's platform cryptography rather than
shipping this package's BoringSSL native asset for Android. It also allows JCA
providers and Android keystore integration to be explored later.

That binary-size benefit does not exist in the current branch. `hook/build.dart` builds and registers the BoringSSL native asset for every code-asset build, and the temporary import wiring selects JNI for every `dart.library.ffi` target. Neither behavior is an Android-specific, user-selectable backend configuration. Draft [#326] changes native linking and adds symbol tree shaking, so the project must re-measure JCA-only output if that work lands; it does not change the current branch result.

## Enabling the backend

There is no supported user-facing way to enable the JCA backend yet. The
exploration branch temporarily imports `impl_jni` on all FFI platforms so the
shared test suite can exercise it.

Issue [#372] tracks the package boundary, registration model, build-hook
behavior, and BoringSSL asset policy for a user-selectable Android backend.

The final design must address all of the following:

* an Android-only opt-in mechanism;
* the `package:jni` Flutter requirement, which creates a package-boundary
  decision for Dart-only `package:webcrypto` users;
* conditional build-hook behavior so JCA-only Android applications do not also
  package BoringSSL; and
* a clear policy for primitives that may remain on another backend.

[Android `Signature` documentation]: https://developer.android.com/reference/java/security/Signature
[#326]: https://github.com/google/webcrypto.dart/pull/326

## Testing locally

For desktop JNI tests, run the JNI setup once from the package root. This
reproduces the current 1,354-pass/88-failure result described above, rather
than a fully green suite:

```sh
dart run jni:setup
dart test test/webcrypto_test.dart -p vm
```

For the complete Android integration suite, run from the demo application:

```sh
flutter test integration_test/webcrypto_test.dart -d emulator-name
```

Focused Android smoke tests are documented in
`example/webcrypto_demo_flutter_app/README.md`.

## Remaining work

* Decide the supported user-facing backend selector and packaging model in
  [#372] before implementing it.
* Add CI coverage for supported Android API levels and ABIs.
* Maintain known provider observations for AES-GCM short tags and RSA-PSS on
  representative supported Android images without treating them as an
  exhaustive provider guarantee.
* Review the stable public exception-category comparison in [#377], while
  allowing provider-specific messages and documented `UnsupportedError`
  capability gaps.
* Make the standalone HKDF and RSA regression tests initialize desktop JNI as
  proposed in [#378].
* Support RSA private PKCS#8 import and private JWK export on providers that do
  not expose imported keys as `RSAPrivateCrtKey`; track the compatibility
  decision in [#371].
* Resolve the PBKDF2 design in [#361] without changing the raw-byte Web Crypto
  contract.
* Review memory ownership, JNI cleanup, JWK validation, and performance before
  treating the backend as production-ready.
