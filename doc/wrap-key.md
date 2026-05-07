# Wrapping Keys with exportKey and encryptBytes

As mentioned in the [Web Crypto API Parity](webcrypto-parity.md) document, the
`wrapKey` and `unwrapKey` operations are omitted from webcrypto.dart because
they can be expressed using key export/import plus encryption/decryption. For
the wrapping algorithms supported by this package, wrapping is:

- export the key in a chosen format,
- encrypt the exported bytes, and
- later decrypt the bytes and import them again.

This tutorial demonstrates how to do that with the APIs that webcrypto.dart
already supports.

In this tutorial, we demonstrate key wrapping using:
- `raw` for symmetric keys,
- `spki` for public keys,
- `pkcs8` for private keys,
- `AES-CBC`, `AES-CTR`, and `AES-GCM` as deterministic wrapping ciphers, and,
- `RSA-OAEP` as a randomized wrapping cipher.

For the canonical byte formats `raw`, `spki`, and `pkcs8`, the wrapped bytes
can match browser `crypto.subtle.wrapKey(...)` output exactly when the same key
material and algorithm parameters are used. For `RSA-OAEP`, ciphertext is
randomized, so the correct parity claim is cross-compatibility when unwrapping,
not byte-for-byte ciphertext equality. For `jwk`, there is an additional caveat
around capability metadata discussed later in this tutorial.

The claims in this document are backed by browser-side tests in
`test/wrap_key_equivalence_test.dart`.

# AES-GCM: Wrapping a Secret Key in raw Format

Symmetric keys are the simplest case. In the Web Crypto API,
`wrapKey("raw", keyToWrap, wrappingKey, ...)` is equivalent to:

1. `exportKey("raw", keyToWrap)`,
2. encrypt the exported bytes with the wrapping key, and,
3. later decrypt those bytes and import them with `importRawKey(...)`.

## Wrapping a raw HMAC key with AES-GCM

To wrap a raw secret key using AES-GCM, follow these steps:

1. Import or generate the AES-GCM wrapping key. We use a 128-bit AES key here:

```dart
final wrappingKey = await AesGcmSecretKey.importRawKey(
  Uint8List.fromList(List<int>.generate(16, (i) => i + 1)),
);
```

2. Import the key that should be wrapped. In this example we wrap an HMAC key:

```dart
final hmacKey = await HmacSecretKey.importRawKey(
  Uint8List.fromList(List<int>.generate(32, (i) => 0x80 + i)),
  Hash.sha256,
);
```

3. Export the HMAC key in `raw` format and encrypt the exported bytes:

```dart
final iv = Uint8List.fromList(List<int>.generate(12, (i) => 0x20 + i));
final additionalData =
    Uint8List.fromList(List<int>.generate(8, (i) => 0x40 + i));

final wrappedKey = await wrappingKey.encryptBytes(
  await hmacKey.exportRawKey(),
  iv,
  additionalData: additionalData,
);
```

At this point `wrappedKey` contains exactly the ciphertext that a browser
`wrapKey("raw", ...)` call would have returned for the same inputs.

4. To unwrap, decrypt the ciphertext and import the result again:

```dart
final unwrappedRaw = await wrappingKey.decryptBytes(
  wrappedKey,
  iv,
  additionalData: additionalData,
);
final unwrappedKey = await HmacSecretKey.importRawKey(
  unwrappedRaw,
  Hash.sha256,
);
```

The `unwrappedKey` is a normal `HmacSecretKey`. It can be used for signing and
verification, just like a key obtained from `crypto.subtle.unwrapKey("raw", ...)`.

## Validating raw key wrapping

The following JavaScript example uses browser `wrapKey("raw", ...)` with fixed
inputs:

```javascript
(async () => {
  const wrappingKeyBytes = Uint8Array.from(
    {length: 16},
    (_, i) => i + 1,
  );
  const hmacKeyBytes = Uint8Array.from(
    {length: 32},
    (_, i) => 0x80 + i,
  );
  const iv = Uint8Array.from({length: 12}, (_, i) => 0x20 + i);
  const additionalData = Uint8Array.from({length: 8}, (_, i) => 0x40 + i);

  const wrappingKey = await crypto.subtle.importKey(
    "raw",
    wrappingKeyBytes,
    {name: "AES-GCM", length: 128},
    true,
    ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
  );
  const hmacKey = await crypto.subtle.importKey(
    "raw",
    hmacKeyBytes,
    {name: "HMAC", hash: "SHA-256"},
    true,
    ["sign", "verify"],
  );

  const jsWrapped = new Uint8Array(await crypto.subtle.wrapKey(
    "raw",
    hmacKey,
    wrappingKey,
    {name: "AES-GCM", iv, additionalData, tagLength: 128},
  ));
  const jsWrappedHex = [...jsWrapped]
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

  console.log("JS_WRAPPED_HEX =", jsWrappedHex);
})();
```

The corresponding Dart code performs `exportRawKey() + encryptBytes(...)` and
verifies that the ciphertext is identical:

```dart
import 'dart:convert' show base64Encode;
import 'dart:typed_data';
import 'package:webcrypto/webcrypto.dart';

Future<void> main() async {
  final wrappingKey = await AesGcmSecretKey.importRawKey(
    Uint8List.fromList(List<int>.generate(16, (i) => i + 1)),
  );
  final hmacKey = await HmacSecretKey.importRawKey(
    Uint8List.fromList(List<int>.generate(32, (i) => 0x80 + i)),
    Hash.sha256,
  );
  final iv = Uint8List.fromList(List<int>.generate(12, (i) => 0x20 + i));
  final additionalData =
      Uint8List.fromList(List<int>.generate(8, (i) => 0x40 + i));

  const jsWrappedHex = '<paste output from JavaScript>';

  final wrappedKey = await wrappingKey.encryptBytes(
    await hmacKey.exportRawKey(),
    iv,
    additionalData: additionalData,
  );
  final dartWrappedHex = wrappedKey
      .map((b) => b.toRadixString(16).padLeft(2, '0'))
      .join();

  final unwrappedRaw = await wrappingKey.decryptBytes(
    wrappedKey,
    iv,
    additionalData: additionalData,
  );

  print('DART_WRAPPED_HEX = $dartWrappedHex');
  print('JS_WRAPPED_HEX   = $jsWrappedHex');
  print('DART_WRAPPED_HEX == JS_WRAPPED_HEX: ${dartWrappedHex == jsWrappedHex}');
  print('UNWRAPPED_RAW_OK = ${base64Encode(unwrappedRaw) == base64Encode(await hmacKey.exportRawKey())}');
}
```

The automated browser test in `test/wrap_key_equivalence_test.dart` verifies
this exact equality for:
- `AES-CBC` wrapping `raw`,
- `AES-CTR` wrapping `raw`, and,
- `AES-GCM` wrapping `raw`.

# AES-GCM: Wrapping Public and Private Keys in spki and pkcs8

Public and private keys work the same way. The only difference is the export
format:
- use `exportSpkiKey()` and `importSpkiKey(...)` for public keys,
- use `exportPkcs8Key()` and `importPkcs8Key(...)` for private keys.

## Wrapping a public key as spki

The following wraps an RSA-OAEP public key as `spki` bytes using AES-GCM:

```dart
final wrappingKey = await AesGcmSecretKey.generateKey(128);
final rsaKeyPair =
    await RsaOaepPrivateKey.generateKey(2048, BigInt.from(65537), Hash.sha256);

final iv = Uint8List(12);
fillRandomBytes(iv);

final wrappedPublicKey = await wrappingKey.encryptBytes(
  await rsaKeyPair.publicKey.exportSpkiKey(),
  iv,
);

final unwrappedSpki = await wrappingKey.decryptBytes(wrappedPublicKey, iv);
final publicKey = await RsaOaepPublicKey.importSpkiKey(
  unwrappedSpki,
  Hash.sha256,
);
```

## Wrapping a private key as pkcs8

The same pattern applies to a private key:

```dart
final wrappedPrivateKey = await wrappingKey.encryptBytes(
  await rsaKeyPair.privateKey.exportPkcs8Key(),
  iv,
);

final unwrappedPkcs8 = await wrappingKey.decryptBytes(wrappedPrivateKey, iv);
final privateKey = await RsaOaepPrivateKey.importPkcs8Key(
  unwrappedPkcs8,
  Hash.sha256,
);
```

For `spki` and `pkcs8`, browser `wrapKey(...)` and the webcrypto.dart
equivalent operate on the same canonical byte sequence. This means
byte-for-byte ciphertext equality is achievable with deterministic wrapping
algorithms such as AES-GCM, provided the same key bytes and parameters are
used.

## Validating spki and pkcs8 wrapping

The automated browser test in `test/wrap_key_equivalence_test.dart` verifies
that:
- `wrapKey("spki", ...)` using AES-GCM matches
  `exportSpkiKey() + encryptBytes(...)` exactly, and,
- `wrapKey("pkcs8", ...)` using AES-GCM matches
  `exportPkcs8Key() + encryptBytes(...)` exactly.

The test also checks the reverse direction:
- ciphertext produced by the package can be passed to browser `unwrapKey(...)`,
  and,
- ciphertext produced by browser `wrapKey(...)` can be decrypted and imported by
  the package.

# RSA-OAEP: Wrapping a Raw Secret Key

`RSA-OAEP` is also a valid wrapping algorithm in the Web Crypto API. In
webcrypto.dart, the equivalent operation is:

1. export the key bytes,
2. encrypt them with `RsaOaepPublicKey.encryptBytes(...)`, and,
3. later decrypt them with `RsaOaepPrivateKey.decryptBytes(...)` and import
   them again.

## Wrapping a raw HMAC key with RSA-OAEP

```dart
final rsaKeyPair =
    await RsaOaepPrivateKey.generateKey(2048, BigInt.from(65537), Hash.sha256);
final hmacKey = await HmacSecretKey.generateKey(Hash.sha256);

final wrappedKey = await rsaKeyPair.publicKey.encryptBytes(
  await hmacKey.exportRawKey(),
  label: const [1, 2, 3, 4],
);

final unwrappedRaw = await rsaKeyPair.privateKey.decryptBytes(
  wrappedKey,
  label: const [1, 2, 3, 4],
);
final unwrappedKey = await HmacSecretKey.importRawKey(
  unwrappedRaw,
  Hash.sha256,
);
```

This is equivalent in behavior to browser
`wrapKey("raw", ..., wrappingKey = rsaPublicKey, {name: "RSA-OAEP", ...})`
followed by `unwrapKey(...)`.

## Validating RSA-OAEP wrapping

Unlike AES-CBC, AES-CTR, and AES-GCM, RSA-OAEP is randomized. Even when the
same key, plaintext, and label are used, two valid ciphertexts will usually be
different. Therefore, browser `wrapKey(...)` and
`exportRawKey() + encryptBytes(...)` should not be expected to return identical
ciphertext bytes.

The correct parity claim is cross-compatibility:
- browser `wrapKey("raw", ...)` output can be decrypted by
  `RsaOaepPrivateKey.decryptBytes(...)`, and,
- package `encryptBytes(...)` output can be passed to browser `unwrapKey(...)`.

The automated browser test in `test/wrap_key_equivalence_test.dart` verifies
exactly that. It confirms that:
- `jsWrapped != dartWrapped`, and,
- both unwrap to the same raw HMAC key bytes.

# JWK: Wrapping JSON Web Keys

For `jwk`, the wrapping flow is still export + encrypt and decrypt + import,
but there is an important difference from the canonical byte formats.

## Wrapping a JWK manually

In the browser, `wrapKey("jwk", ...)` serializes a JWK JSON object and wraps
those bytes. In webcrypto.dart, the equivalent manual flow is:

```dart
import 'dart:convert';
import 'dart:typed_data';
import 'package:webcrypto/webcrypto.dart';

final wrappingKey = await AesGcmSecretKey.generateKey(128);
final hmacKey = await HmacSecretKey.generateKey(Hash.sha256);

final iv = Uint8List(12);
fillRandomBytes(iv);

final wrappedJwk = await wrappingKey.encryptBytes(
  utf8.encode(jsonEncode(await hmacKey.exportJsonWebKey())),
  iv,
);

final decryptedJwkJson = jsonDecode(
  utf8.decode(await wrappingKey.decryptBytes(wrappedJwk, iv)),
) as Map<String, dynamic>;

final unwrappedKey = await HmacSecretKey.importJsonWebKey(
  decryptedJwkJson,
  Hash.sha256,
);
```

This reconstructs the same key material, but the JSON payload is not always
identical to browser `wrapKey("jwk", ...)`.

## The JWK caveat: ext and key_ops

The Web Crypto API associates capability metadata with keys:
- `CryptoKey.extractable`,
- `CryptoKey.usages`.

When a browser exports or unwraps a `jwk`, these values can appear as:
- `ext`, and,
- `key_ops`.

webcrypto.dart intentionally does not expose capability bits as part of its
public API, and its browser implementation strips `ext` and `key_ops` during
JWK import/export. As a result:

- browser `wrapKey("jwk", ...)` can produce wrapped JSON that includes `ext`
  and `key_ops`,
- `exportJsonWebKey()` in webcrypto.dart omits those fields, and,
- byte-for-byte JWK ciphertext equality should not be claimed.

The automated browser test in `test/wrap_key_equivalence_test.dart` verifies
the precise boundary:
- decrypting the browser wrapped JWK reveals `ext` and `key_ops`,
- decrypting the package wrapped JWK does not include those fields, and,
- after removing `ext` and `key_ops` from the browser JSON, the remaining JWK
  members match exactly.

Because of this, `jwk` should be documented as:
- the same key material after decrypt + import, but,
- not full capability-bit parity with browser `unwrapKey("jwk", ...)`.

# AES-KW

`AES-KW` is not covered by this tutorial.

The Web Crypto API allows `AES-KW` to be used with `wrapKey` and `unwrapKey`,
but webcrypto.dart does not expose `AES-KW`, and it does not expose the lower
level AES block primitive needed to reconstruct AES-KW directly from the public
API. For that reason, this tutorial only claims parity for wrapping algorithms
already supported through `encryptBytes(...)` and `decryptBytes(...)`.

# Conclusion

In this tutorial, we demonstrated how to wrap and unwrap keys in
webcrypto.dart using export/import together with encryption/decryption,
achieving parity with the Web Crypto API's `wrapKey` and `unwrapKey`
functionality for the supported wrapping algorithms.

For `raw`, `spki`, and `pkcs8`, the package can match browser behavior exactly:
export the canonical bytes, encrypt them, decrypt them, and import them again.
For `RSA-OAEP`, the behavior is cross-compatible but ciphertext is randomized,
so equality should be checked after unwrapping. For `jwk`, the key material is
equivalent, but browser capability metadata (`ext` and `key_ops`) is outside
the package's parity claim.
