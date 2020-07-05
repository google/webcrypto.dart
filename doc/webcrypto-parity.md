Notes on Parity with the Web Cryptography Specification
=======================================================

The design outlined in this package attempts to be a reasonably typed variant of
the API exposed in the [Web Cryptography Specification][1] (see also
[Web Crypto API on MDN][2]). However, this package does not have complete
feature equivalence with the Web Crypto API.

This package is slightly more powerful in that methods like
encrypt/decrypt/sign/verify accepts data as `Stream<List<int>>`, which allows
for streaming, whereas the Web Crypto API only accepts byte buffers. The browser
implementation of this package hides this by buffering the stream before calling
into the browsers Web Crypto API. While the native implementation is able to
stream the data encrypting/decrypting chunk by chunk.

In the other direction the Web Crypto API offers a few features this package
does not expose. Mostly because typing would be awkward/complex and the utility
is low as these are mostly convenience methods. These are:

 * Key capabilities expressed in `CryptoKey.usages` and `CryptoKey.extractable`,
 * `crypto.subtle.deriveKey`,
 * `crypto.sutble.wrapKey` / `crypto.sutble.wrapKey`, and,
 * The `'AES-KW'` algorithm.

[1]: https://www.w3.org/TR/WebCryptoAPI/
[2]: https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto

## Notes on `CryptoKey` capability bits
In the Web Crypto APIs the `CryptoKey` has properties `CryptoKey.usages` and
`CryptoKey.extractable` which specify what operations a key may do, and whether
or not it can be exported. Specifying such capabilities on key objects allows
developers to harden their applications against accidental misuse of keys.

If we wanted to support this feature we would introduce a `KeyUsages` enum, and
allow all key import and generation methods to accept a set of usages, as well
as an `extractable` bit. Various key opertions would then throw
`UnsupportedError` if the key capabilities is violated.

This is not an unreasonable API design. However, this feature can also be
implemented in a high-level crypto package wrapping the API offered by this
package. Furthermore, if we wanted to introduce this later we could easily add
optional `usages` and `extractable` parameters to all key import and generation
methods.

**Conclusion**, as the capability bits are exclusively intended to harden code
against mistakes, and this can be done independently in a high level wrapper,
this package shall omit this feature. Adding capability bits
to keys in the future would be non-breaking, so long as they remain optional.

## Notes on `deriveKey`
In the Web Crypto API algorithms `'ECDH'`, `'HKDF'` and `'PBKDF2'` can be used
with the `crypto.subtle.deriveBits` operation which returns bits derived
through key stretching (HKDF/PBKDF2) or public/private exchanges (ECDH). This
operation is also exposed through the instance method `deriveBits` on key-types
`EcdhPrivateKey`, `Pbkdf2SecretKey` and `HkdfSecretKey`.

However, the equivalent `CryptoKey` object in the Web Crypto API can also be
used with `crypto.sutble.deriveKey` operation, which returns a `CryptoKey`
created with the bits from `deriveBits`. But the `deriveKey` operation can only
be used to derive keys for AES variants. Thus, since it's trivial to call
`deriveBits` and then pass the result to the `importRawKey` function for
any of the AES key variants, the `deriveKey` operation is redundant.

The primary motivation to feature the `deriveKey` operation would be that
a `KeyUsage` enum would be able to contain both `deriveKey` and `deriveBits`.
Limiting a key to specific usages when it is created is a nice way to harden
your code against mistakes. But it's hardly a critical feature, as authors are
responsible for locking down their own keys.

If we wanted to support this feature we could introduce a type
`DeriveKeyOptions<T extends CryptoKey>` and place a static method for creating
a `DeriveKeyOptions<T>` on each of the key-types that can be derived.
For example, `AesGcmSecretKey` would have a static method 
`AesGcmSecretKey.deriveKeyOptions()` which returns a
`DeriveKeyOptions<AesGcmSecretKey>` instance. The deriving key types
(`EcdhPrivateKey`, `Pbkdf2SecretKey` and `HkdfSecretKey`) would then have an
instance method `deriveKey<T>() -> T` which accepts a `DeriveKeyOptions<T>`
instance ensuring the return value is properly typed.

This approach is reasonably elegant, offers a typed API, but has the downside of
introducing an awkward type `DeriveKeyOptions<T>` which is something consumers
can't implement or interact with, the only valid usage is to pass instance of
this object between two black boxes.

**Conclusion**, as the `deriveKey` operation is fully redundant and the option
for supporting it has complex typing, this package shall omit this operation.
Adding the operation in the future would only impact developers who have custom
implementations of the `EcdhPrivateKey`, `Pbkdf2SecretKey` and `HkdfSecretKey`
classes. And these types don't invite custom implementations, so this would
probably not be very breaking.

## Notes on `crypto.sutble.wrapKey` / `crypto.sutble.unwrapKey`
In the Web Crypto API all algorithms that support encrypt/decrypt operations
also support the `crypto.sutble.wrapKey` and `crypto.sutble.unwrapKey`
operations. These operations are also supported by the `'AES-KW'` which only
supports the wrap/unwrap key operations.

Wrapping a key is to encrypt the key with another key. This is equivalent to
exporting a key in given key-format and encrypting the exported result with
another key. Similarly, unwrapping a key is to decrypt a key with another key.
This also equivalent to decrypting the key and then importing the key.

Similar to `deriveKey` this is useful when limiting a key to specific usages to
prevent a key from accidentally being misused. If we wanted to support this
feature we would also be introducing intermediate objets similar to the design
outlined for `deriveKey`. Instead these would be `WrapKeyOptions` and
`UnwrapKeyOptions<T>`, and keys that can be wrapped would have methods for
creating these options with different encapsulated key-formats.

**Conclusion**, as key wrapping and unwrapping can be implemented with
export+encrypt and decrypt+import and it has complex typing, this package shall
omit this functionality. Adding these operations in the future only impact
developers who have custom implementations of `CryptoKey` subclasses.

## Notes on the `'AES-KW'` Algorithm
The `'AES-KW'` algorithm only supports the `crypto.sutble.wrapKey` and
`crypto.sutble.unwrapKey` operations, which we have argued to omit in the
previous section. Hence, this package shall omit this algorithm.
