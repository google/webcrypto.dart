# Deriving Keys with deriveBits and importRawKey

As mentioned in the [Web Crypto API Parity](webcrypto-parity.md) document, the deriveKey operation is fully redundant and the option for supporting it has complex typing. For this reason webcrypto.dart shall omit this operation. Instead, users can derive bits using the `deriveBits` method on key-types `EcdhPrivateKey`, `Pbkdf2SecretKey` and `HkdfSecretKey`, and then import the raw bits using the `importRawKey` function for any of the AES key variants.

This tutorial demonstrates how to derive cryptographic keys using the supported deriveBits method for all relevant algorithms.

In this tutorial, we demonstrate key derivation using:
- ECDH (Elliptic Curve Diffie–Hellman) – deriving a shared secret from two key pairs.
- HKDF (HMAC-based Key Derivation Function) – deriving a new key from an initial key and cryptographic salt/info.
- PBKDF2 (Password-Based Key Derivation Function 2) – deriving a secure key from a password, salt, and iteration count.

For each scenario, we will derive raw key material (bytes) using `deriveBits`, then import those bytes as a usable key (for example, an AES key for encryption). The derived key will be identical to what the Web Crypto API’s `deriveKey` would produce, thus achieving parity without needing a direct `deriveKey` method.

# ECDH: Deriving a Shared Secret Key

Elliptic Curve Diffie–Hellman (ECDH) allows two parties to generate a mutual secret using their private keys and each other’s public keys. In webcrypto.dart, you can derive a shared secret as an array of bytes and then turn it into a symmetric key. 

## Deriving a shared secret with ECDH

To derive a 256-bit AES key from an ECDH exchange, follow these steps:

1. Generate ECDH key pairs for both parties. Each party (say Alice and Bob) creates an elliptic-curve key pair. In this example we use the P-256 curve:

```dart
final aliceKeyPair = await EcdhPrivateKey.generateKey(EllipticCurve.p256);
final bobKeyPair = await EcdhPrivateKey.generateKey(EllipticCurve.p256);
```

Each `KeyPair` contains a private key and the corresponding public key. Alice will use her private key and Bob’s public key (and vice versa) in the next step.

2. Derive the shared secret bits using one private key and the other party’s public key. The deriveBits method on an ECDH private key takes the number of bits to derive and the other party’s public key:

```dart
final sharedSecretAlice = await aliceKeyPair.privateKey.deriveBits(
  256,                        // derive a 256-bit secret
  bobKeyPair.publicKey,       // Bob's public key
);

// Bob independently derives the same 256-bit secret using Alice's public key:
final sharedSecretBob = await bobKeyPair.privateKey.deriveBits(
    256,                    // derive a 256-bit secret
    aliceKeyPair.publicKey  // Alice's public key
);
assert(base64.encode(sharedSecretAlice) == base64.encode(sharedSecretBob));
```

After this step, both `sharedSecretAlice` and `sharedSecretBob` contain the same 32 bytes (256 bits) of shared secret. We verify this by checking that their Base64 encodings match. In a real-world scenario, Alice and Bob would exchange public keys beforehand to perform this derivation.

3. Import the derived bits as a symmetric key. Now that we have raw key material, we can create a usable key object. For example, to use the shared secret for AES-GCM encryption, import the 32-byte secret as an AES key:

```dart
final key = await AesGcmSecretKey.importRawKey(sharedSecretAlice);
```

The `key` is a fully functional AesGcmSecretKey. It can be used for encryption and decryption (with an IV). The important part is that this key was derived from the ECDH exchange. In the Web Crypto API, calling `deriveKey` with ECDH and AES-GCM would produce the same result as the above two steps of derive-then-import.

## Validating the ECDH Key Derivation

The library’s approach is to use `deriveBits` and then import the result to get a `key`. Given the above, we expect that deriving keys in webcrypto.dart will produce the same raw bytes as deriving keys in the browser’s Web Crypto API, provided the same inputs are used. This section shows a cross-environment example using the same ECDH parameters in both JavaScript and Dart, proving that the derived key material matches exactly. This cross-check demonstrates that webcrypto.dart’s derived bits are fully compatible with browser-derived keys, thanks to conforming to the same ECDH algorithm and parameters.

1. Derive key in the browser (JavaScript) – In a browser console (or Node environment with Web Crypto), derive a key using the Web Crypto API. We'll use ECDH with the P-256 curve to derive a 256-bit AES key.

```javascript
(async () => {
  // Generate P-256 key pair for Alice & Bob
  const alice = await crypto.subtle.generateKey({name:"ECDH", namedCurve:"P-256"},
                                               true, ["deriveKey"]);
  const bob   = await crypto.subtle.generateKey({name:"ECDH", namedCurve:"P-256"},
                                               true, ["deriveKey"]);

  // Export JWK so Dart can import them
  const alicePrivJwk = await crypto.subtle.exportKey("jwk", alice.privateKey);
  const bobPubJwk    = await crypto.subtle.exportKey("jwk", bob.publicKey);
  console.log("ALICE_PRIV =", JSON.stringify(alicePrivJwk));
  console.log("BOB_PUB    =", JSON.stringify(bobPubJwk));

  // Alice derives AES-GCM-256 shared key
  const jsShared = await crypto.subtle.deriveKey(
    {name:"ECDH", namedCurve:"P-256", public: bob.publicKey},
    alice.privateKey,
    {name:"AES-GCM", length:256},
    true,
    ["encrypt"]
  );

  const jsSharedHex = [...new Uint8Array(
    await crypto.subtle.exportKey("raw", jsShared)
  )].map(b=>b.toString(16).padStart(2,"0")).join("");
  console.log("JS_SHARED_HEX =", jsSharedHex);
})();
```

This will produce a result of the following structure:
```javascript
ALICE_PRIV = {"crv":"P-256","d":"Aeps684VtTRxdFbkWPbFkJUYDVm2Pp7XbKK2hQhen74","ext":true,"key_ops":["deriveKey"],"kty":"EC","x":"6ksgNbR_n_70qGAB-Kzd4i9CltSSz0oRb0SSQGQzVY0","y":"bk6dSGfXMWRHHbgzVXGyheh4TzlCK8G-VO_HZmmAhLA"}
BOB_PUB    = {"crv":"P-256","ext":true,"key_ops":[],"kty":"EC","x":"7-W_ZOpHESDmNLOTuKgl_xFMCPStgj8H3gCglGmaukQ","y":"Eq8HBiXqvJdWpirK3BRFaCXTHFTGQ04ruGa7Wdli4NE"}
JS_SHARED_HEX = 4e10635123e6365db75890a89a67017e616bf3ea899b549670d56f20a45c8f69
```

2. Derive key in Dart using webcrypto.dart – Now we can derive the same key in Dart using the webcrypto.dart library. We will use the same ECDH parameters and import the raw key material to verify it matches the JavaScript result. We will use the JWKs exported from the JavaScript code above to derive the same shared key.

```dart
import 'dart:typed_data';
import 'package:webcrypto/webcrypto.dart';

Map<String, dynamic> alicePrivJwk = {
  "crv": "P-256",
  "d": "Aeps684VtTRxdFbkWPbFkJUYDVm2Pp7XbKK2hQhen74",
  "ext": true,
  "key_ops": ["deriveKey"],
  "kty": "EC",
  "x": "6ksgNbR_n_70qGAB-Kzd4i9CltSSz0oRb0SSQGQzVY0",
  "y": "bk6dSGfXMWRHHbgzVXGyheh4TzlCK8G-VO_HZmmAhLA"
};
Map<String, dynamic> bobPubJwk = {
  "crv": "P-256",
  "ext": true,
  "key_ops": [],
  "kty": "EC",
  "x": "7-W_ZOpHESDmNLOTuKgl_xFMCPStgj8H3gCglGmaukQ",
  "y": "Eq8HBiXqvJdWpirK3BRFaCXTHFTGQ04ruGa7Wdli4NE"
};
const jsSharedHex = '4e10635123e6365db75890a89a67017e616bf3ea899b549670d56f20a45c8f69';

Uint8List hexToBytes(String h) => Uint8List.fromList(List.generate(
    h.length ~/ 2, (i) => int.parse(h.substring(i * 2, i * 2 + 2), radix: 16)));

void main() async {
  final alicePriv =
      await EcdhPrivateKey.importJsonWebKey(alicePrivJwk, EllipticCurve.p256);
  final bobPub =
      await EcdhPublicKey.importJsonWebKey(bobPubJwk, EllipticCurve.p256);

  final bits = await alicePriv.deriveBits(256, bobPub);
  final dartKey = await AesGcmSecretKey.importRawKey(bits);

  final dartHex = (await dartKey.exportRawKey())
      .map((b) => b.toRadixString(16).padLeft(2, '0'))
      .join();

  print('DART_SHARED_HEX = $dartHex');
  print('JS_SHARED_HEX   = $jsSharedHex');
  print('DART_SHARED_HEX == JS_SHARED_HEX: ${dartHex == jsSharedHex}');
}
```

This Dart code imports the same JWKs generated in JavaScript, derives the shared secret using ECDH, and then imports it as an AES-GCM key. The final output will show that the derived key in Dart matches the one derived in JavaScript.

Upon execution of the Dart code, you would observe the following:
```shell
DART_SHARED_HEX = 4e10635123e6365db75890a89a67017e616bf3ea899b549670d56f20a45c8f69
JS_SHARED_HEX   = 4e10635123e6365db75890a89a67017e616bf3ea899b549670d56f20a45c8f69
DART_SHARED_HEX == JS_SHARED_HEX: true
```

This confirms that the derived key material from ECDH in Dart matches the JavaScript Web Crypto API result, demonstrating that webcrypto.dart’s ECDH key derivation is fully compatible with the browser’s implementation.

# HKDF: Deriving a Key from an Initial Key and Salt

HKDF is a key derivation function used to expand a source key into one or more new keys, using a salt and an optional info context. With webcrypto.dart, you start with an HkdfSecretKey (holding the initial key material) and derive bytes from it. Those bytes can then be imported as a new key for use in encryption or other cryptographic operations.

## Deriving a key with HKDF

To derive a new key using HKDF, follow these steps:

1. Import the initial key material into an HkdfSecretKey. This initial key could be a raw secret byte array or a password. For illustration, we’ll use a simple byte array (in practice, use a high-entropy secret):

```dart
final masterKeyData = utf8.encode('master-key');            // initial key material (as bytes)
final hkdfKey = await HkdfSecretKey.importRawKey(masterKeyData);
```

Here `masterKeyData` represents the input keying material (IKM) for HKDF. In a real scenario, this might come from an ECDH shared secret or another source of entropy. We import this to get an HkdfSecretKey object.

2. Derive key bits with a salt and info. Use the deriveBits method on the hkdfKey, specifying the output length, hash function, salt, and info:

```dart
final salt = utf8.encode('unique salt');        // A non-secret salt value (should be random for each derivation)
final info = utf8.encode('context info');       // Optional context string
final derivedBits = await hkdfKey.deriveBits(
  256,             // derive 256 bits
  Hash.sha256,     // use SHA-256 in HKDF
  salt,
  info,
);
```
We derive 256 bits using HKDF with SHA-256. The `salt` should be a unique, ideally random, byte sequence for each derivation to ensure independence of keys. The info parameter is optional context data – it can be an empty list or a string describing the purpose of the derived key.

3. Import the derived bits as a new key. The output of HKDF (derivedBits) is a byte array which we can now use to create a cryptographic key. For example, to create an AES key for GCM encryption from these bits:

```dart
final key = await AesGcmSecretKey.importRawKey(derivedBits);
```

Now `key` is an `AesGcmSecretKey` that can be used for encryption/decryption. We effectively simulated what a direct `deriveKey` call would do: derive 256 bits from a master key and turn them into an AES key. You could similarly import the bits into an `AesCbcSecretKey`, `HmacSecretKey`, or any other suitable key type depending on your needs.

## Validating the HKDF Key Derivation

In this section, we will validate that the derived key material from HKDF in webcrypto.dart matches the expected output from the Web Crypto API. This ensures that our HKDF implementation is compatible with browser-derived keys.

1. Derive key in the browser (JavaScript) – In a browser console (or Node environment with Web Crypto), derive a key using the Web Crypto API. We'll use HKDF to derive a 256-bit AES key.

```javascript
// Browser JavaScript (DevTools console)
(async () => {
  const enc = new TextEncoder();

  // 32-byte base key material – keep hex so Dart can reuse it
  const baseBytes = crypto.getRandomValues(new Uint8Array(32));
  const baseHex   = [...baseBytes].map(b=>b.toString(16).padStart(2,"0")).join("");
  console.log("BASE_HEX =", baseHex);

  const baseKey = await crypto.subtle.importKey(
    "raw", baseBytes, {name:"HKDF"}, false, ["deriveKey"]
  );

  const hkdfParams = {
    name: "HKDF",
    salt: enc.encode("hkdf-salt"),
    info: enc.encode("context"),
    hash: "SHA-256",
  };

  const jsKey = await crypto.subtle.deriveKey(
    hkdfParams,
    baseKey,
    {name:"AES-GCM", length:256},
    true,
    ["encrypt"]
  );

  const jsHex = [...new Uint8Array(
    await crypto.subtle.exportKey("raw", jsKey)
  )].map(b=>b.toString(16).padStart(2,"0")).join("");

  console.log("JS_AES_HEX =", jsHex);
})();
```

This will produce a result of the following structure:
```shell
BASE_HEX = 30559b92b401b02f9e5b0cfed5e4e6dc9e3e551f93b29f04cd27baa2d055c835
JS_AES_HEX = 80eaada1ce52bb265c1796155e50dd05deafc959f389a87a9fe139f12bcc0e1f
```

2. Derive key in Dart using webcrypto.dart – Now we can derive the same key in Dart using the webcrypto.dart library. We will use the same HKDF parameters and import the raw key material to verify it matches the JavaScript result. We will use the base key material generated in JavaScript to derive the same AES key.

```dart
import 'dart:convert';
import 'dart:typed_data';
import 'package:webcrypto/webcrypto.dart';

const baseHex =
    '30559b92b401b02f9e5b0cfed5e4e6dc9e3e551f93b29f04cd27baa2d055c835';
const jsHex =
    '80eaada1ce52bb265c1796155e50dd05deafc959f389a87a9fe139f12bcc0e1f';

Uint8List hexToBytes(String h) => Uint8List.fromList(List.generate(
    h.length ~/ 2, (i) => int.parse(h.substring(i * 2, i * 2 + 2), radix: 16)));

void main() async {
  final hkdfBase = await HkdfSecretKey.importRawKey(hexToBytes(baseHex));

  final derivedBits = await hkdfBase.deriveBits(
    256,
    Hash.sha256,
    utf8.encode('hkdf-salt'),
    utf8.encode('context'),
  );

  final dartKey = await AesGcmSecretKey.importRawKey(derivedBits);
  final dartHex = (await dartKey.exportRawKey())
      .map((b) => b.toRadixString(16).padLeft(2, '0'))
      .join();

  print('DART_AES_HEX = $dartHex');
  print('JS_AES_HEX   = $jsHex');
  print('DART_AES_HEX == JS_AES_HEX: ${dartHex == jsHex}');
}
```

This Dart code imports the base key material generated in JavaScript, derives the AES key using HKDF, and then imports it as an AES-GCM key. The final output will show that the derived key in Dart matches the one derived in JavaScript.

Upon execution of the Dart code, you would observe the following:
```shell
DART_AES_HEX = 80eaada1ce52bb265c1796155e50dd05deafc959f389a87a9fe139f12bcc0e1f
JS_AES_HEX   = 80eaada1ce52bb265c1796155e50dd05deafc959f389a87a9fe139f12bcc0e1f
DART_AES_HEX == JS_AES_HEX: true
```

This confirms that the derived key material from HKDF in Dart matches the JavaScript Web Crypto API result, demonstrating that webcrypto.dart’s HKDF key derivation is fully compatible with the browser’s implementation.

# PBKDF2: Deriving a Key from a Password

PBKDF2 is a password-based KDF used to derive cryptographic keys from low-entropy secrets (like user passwords) by applying a salt and many hash iterations. With webcrypto.dart, a `Pbkdf2SecretKey` holds the password, and deriveBits produces key material from it. We can then import those bits as a key for encryption or HMAC.

## Deriving a key with PBKDF2
To derive a key using PBKDF2, follow these steps:

1. Import the password into a `Pbkdf2SecretKey`. We take a plaintext password and import it as raw key data (note: in real applications, never store or reuse the raw password bytes directly – this is just for derivation in memory):

```dart
final password = utf8.encode('correcthorsebatterystaple');
final pbkdf2Key = await Pbkdf2SecretKey.importRawKey(password);
```

The `pbkdf2Key` now represents the password and can be used to derive cryptographic keys using PBKDF2. Ensure you use a unique random salt for each password and a high iteration count to make brute-force attacks impractical.

2. Derive key bits with salt and iterations. We use deriveBits on the pbkdf2Key, specifying the output length, hash, salt, and the number of iterations:

```dart
final salt = utf8.encode('unique salt');    // A unique salt for this password (public but should be random)
final iterations = 100000;                 // Number of hash iterations (e.g., 100k or more)
final derivedBits = await pbkdf2Key.deriveBits(
  256,            // derive 256-bit key
  Hash.sha256,    // use HMAC-SHA256 as the PRF
  salt,
  iterations,
);
```

We derive a 256-bit key using PBKDF2 with SHA-256. The salt in PBKDF2, like in HKDF, should be random and unique for each password. The `iterations` count should be set as high as is feasible (e.g., 100k or even more) to increase the computation cost for attackers. The output `derivedBits` will be the same bytes that a Web Crypto `deriveKey` call would have produced with the same parameters.

3. Import the derived bits as a new key. Finally, convert the PBKDF2 output into a key object, for example an AES key for encryption:

```dart
final encryptionKey = await AesGcmSecretKey.importRawKey(derivedBits);
```

The encryptionKey can now be used for AES encryption/decryption. This is equivalent to using crypto.subtle.deriveKey in a browser with PBKDF2 to get an AES key – we derived the raw key material and then imported it.

## Validating the PBKDF2 Key Derivation

In this section, we will validate that the derived key material from PBKDF2 in webcrypto.dart matches the expected output from the Web Crypto API. This ensures that our PBKDF2 implementation is compatible with browser-derived keys.

1. Derive key in the browser (JavaScript) – In a browser console (or Node environment with Web Crypto), derive a key using the Web Crypto API. We'll use PBKDF2 to derive a 256-bit AES key from a password.

```javascript
(async () => {
  const enc = new TextEncoder();
  const password   = enc.encode("correct horse battery staple");
  const salt       = enc.encode("demo-salt");          // fixed so the test is deterministic
  const iterations = 100_000;

  // Import password as a PBKDF2 base key
  const pwKey = await crypto.subtle.importKey(
    "raw", password, {name:"PBKDF2"}, false, ["deriveKey"]
  );

  // **deriveKey** → AES-GCM (256 bit)
  const aesKey = await crypto.subtle.deriveKey(
    {name:"PBKDF2", salt, iterations, hash:"SHA-256"},
    pwKey,
    {name:"AES-GCM", length:256},
    true,
    ["encrypt","decrypt"]
  );

  // Export key as raw bytes and print as hex
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", aesKey));
  const hex = [...raw].map(b=>b.toString(16).padStart(2,"0")).join("");
  console.log("REFERENCE_HEX =", hex);
})();
```

This will produce a result of the following structure:
```javascript
44ca28d53395e39b8ecc67e6449f002a5239b4f86023ee54d76a1da28510f388
```

2. Derive key in Dart using webcrypto.dart – Now we can derive the same key in Dart using the webcrypto.dart library. We will use the same PBKDF2 parameters and import the raw key material to verify it matches the JavaScript result.

```dart
import 'dart:convert';
import 'package:webcrypto/webcrypto.dart';

Future<void> main() async {
  final password = utf8.encode('correct horse battery staple');
  final salt = utf8.encode('demo-salt');
  const iterations = 100000;
  const referenceHex =
      '44ca28d53395e39b8ecc67e6449f002a5239b4f86023ee54d76a1da28510f388';

  // Import password
  final pbk = await Pbkdf2SecretKey.importRawKey(password);

  // **deriveBits** (256 bits) then import as AES-GCM key
  final bits = await pbk.deriveBits(256, Hash.sha256, salt, iterations);

  final aesKey = await AesGcmSecretKey.importRawKey(bits);

  // Export raw bytes and print hex
  final raw = await aesKey.exportRawKey();
  final hex = raw.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  print('DART_HEX      = $hex');
  print('REFERENCE_HEX = $referenceHex');
  print('DART_HEX == REFERENCE_HEX: ${hex == referenceHex}');
}
```

This Dart code imports the password, derives the AES key using PBKDF2, and then imports it as an AES-GCM key. The final output will show that the derived key in Dart matches the one derived in JavaScript.

Upon execution of the Dart code, you would observe the following:
```shell
DART_HEX      = 44ca28d53395e39b8ecc67e6449f002a5239b4f86023ee54d76a1da28510f388
REFERENCE_HEX = 44ca28d53395e39b8ecc67e6449f002a5239b4f86023ee54d76a1da28510f388
DART_HEX == REFERENCE_HEX: true
```

This confirms that the derived key material from PBKDF2 in Dart matches the JavaScript Web Crypto API result, demonstrating that webcrypto.dart’s PBKDF2 key derivation is fully compatible with the browser’s implementation.

# Conclusion

In this tutorial, we demonstrated how to derive cryptographic keys using the `deriveBits` method in webcrypto.dart, achieving parity with the Web Crypto API's `deriveKey` functionality. We covered three key derivation methods: ECDH for shared secrets, HKDF for expanding keys, and PBKDF2 for deriving keys from passwords.

By deriving raw key material and importing it as usable keys, we can effectively perform key derivation without needing a direct `deriveKey` method.
