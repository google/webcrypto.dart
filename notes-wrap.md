

```dart



final unwrappedKey = secretKey.unwrap(
  wrappedKeyInBytes,
);
final hmacKey = HmacSecretKey.importUnwrappedKey(unwrappedKey, Hash.sha256);





final hmacKey = await HmacSecretKey.generate(Hash.sha256);

final wrappedKeyAsBytes = secretKey.wrapKey(hmacKey, iv);

final hmacKey = await secretKey.unwrap(
  wrappedKeyAsBytes,
  HmacSecretKey.options(Hash.sha256),
  iv,
)




final hmacKey = hkdfKey.deriveKey(
  HmacSecretKey.options(Hash.sha256),
  salt,
  info,
)

// ---------------------------------------


final hmacKey = await HmacSecretKey.generate(Hash.sha256);

final wrappedKeyAsBytes = secretKey.wrapKey(hmacKey, iv);

final hmacKey = await HmacSecretKey.importWrappedKey(
  secretKey.unwrapKey(wrappedKeyAsBytes, iv),
  Hash.sha256,
);

final hmacKey = await HmacSecretKey.importDerivedKey(
  hkdfKey.deriveKey(salt, info),
  Hash.sha256,
);


// ---------------------------------------


final hmacKey = await HmacSecretKey.generate(Hash.sha256);

final wrappedKeyAsBytes = secretKey.wrapKey(hmacKey, iv);

final hmacKey = await HmacSecretKey.importOpaqueKey(
  secretKey.unwrapKey(wrappedKeyAsBytes, iv), // returns OpaqueKey
  Hash.sha256,
);

final hmacKey = await HmacSecretKey.importOpaqueKey(
  hkdfKey.deriveKey(salt, info), // returns OpaqueKey
  Hash.sha256,
);


@sealed
abstract class OpaqueKey {}

// ---------------------------------------


final hmacKey = await HmacSecretKey.generate(Hash.sha256);

final wrappedKeyAsBytes = await secretKey.wrapJsonWebKey(hmacKey, iv);

final hmacKey = await secretKey
    .unwrapJsonWebKey(wrappedKeyAsBytes, iv)
    .asHmacSecretKey(Hash.sha256);

final hmacKey = await hkdfKey
  .deriveKey(salt, info)
  .asHmacSecretKey(Hash.sha256);

@sealed
abstract class OpaqueKey {
  Future<HmacSecretKey> asHmacSecretKey(Hash hash);
}

// ---------------------------------------

// Note: I do not like the naming, it allows for the right typing, but these
//       are not good names, they will not be located next to each other in
//       generated documentation or in code completion.
abstract class JsonWebExportableKey {
  Future<Map<String, dynamic>> exportJsonWebKey();
}
abstract class RawExportableKey {
  Future<Uint8List> exportRawKey();
}
abstract class SpkiExportableKey {
  Future<Uint8List> exportSpkiKey();
}
abstract class Pkcs8ExportableKey {
  Future<Uint8List> exportPkcs8Key();
}

final hmacKey = await HmacSecretKey.generate(Hash.sha256);

// It's weird that wrap<format>Key has the format in the method name.
// but unwrapKey doesn't have format in the name.
final = wrappedKeyAsBytes await secretKey.wrapJsonWebKey(
  hmacKey, // this is a JsonWebExportableKey
  iv,
);

final = wrappedKeyAsBytes await secretKey.wrapRawKey(
  hmacKey, // this is a JsonWebExportableKey
  iv,
);


final hmacKey = await secretKey.unwrapKey(
  // This must be a ImportKeyOptions<T>, and then unwrapKey returns Future<T>
  // This allows us to ensure:
  //   - Typing when specifying HMAC import parameters
  //   - Prevents the user from trying using SPKI with options belonging to
  //     a private RsaPssPrivateKey which doesn't support importSpkiKey(...)
  //
  // Note: I do not like the naming
  HmacSecretKey.importJsonWebKeyOptions(Hash.sha256),
  wrappedKeyAsBytes,
  iv,
);

final hmacKey = await secretKey.unwrapKey(
  HmacSecretKey.importRawKeyOptions(Hash.sha256),
  wrappedKeyAsBytes,
  iv,
);

final hmacKey = await hkdfKey.deriveKey(
  // This must be a DeriveKeyOptions<T>, and then deriveKey returns Future<T>
  // This allows us to limit what keys can be derived, webcrypto can only derive
  // HMAC, AES-CBC, AES-CTR, AES-GCM and AES-KW. 
  HmacSecretKey.deriveKeyOptions(Hash.sha256),
  salt,
  info,
);

@sealed
abstract class ImportKeyOptions<T> {}

@sealed
abstract class DeriveKeyOptions<T> {}

// We could do: ImportJsonWebKeyOptions, as illustrated below.
// Then HmacSecretKey.importJsonWebKeyOptions would return a
// ImportJsonWebKeyOptions<HmacSecretKey>
//
// So users would be able to do:
// final hmacKey = await HmacSecretKey.importJsonWebKeyOptions(Hash.sha256).import(
//  json.decode(jwt),
// );
//
// So one could even argue that it would make unnecessary to have:
// final hmacKey = await HmacSecretKey.importJsonWebKey(
//   json.decode(jwt),
//   Hash.sha256,
// );
// I'm not sure this is a good idea. Because it promotes doing things like:
//   final opts = HmacSecretKey.importJsonWebKeyOptions(Hash.sha256);
// And then later doing:
//   ... = opts.import(...);
// And I'm not sure we should provide that level of abstractions. It might be
// somewhat risky to separate these things.
// Also some people might get the idea that an ImportJsonWebKeyOptions is
// something that can be implemented -- which it can't.
// Indeed: ImportKeyOptions having no members makes it clear that this is an
//         opaque object, not an interface that can be satisfied by the user.
abstract class ImportJsonWebKeyOptions<T> implements ImportKeyOptions<T> {
  Future<T> import(Map<String, dynamic> jwk);
}


// ---------------------------------------

final hmacKey = await HmacSecretKey.generate(Hash.sha256);


final = wrappedKeyAsBytes await secretKey.wrapKey(
  // This is a WrapKeyInput
  // each xxxKey type can implement: wrappable<format>Key() -> WrapKeyInput
  // Typing ensures you won't try to wrap an HMAC key as SPKI, because
  // you simply cannot express it.
  hmacKey.asRawWrapKeyInput(), // better name please!
  // These are the same options as secretKey.encryptBytes, which differs
  // depending on the type of [secretKey] -- which is typed! :D
  iv,
);


final hmacKey = await secretKey.unwrapKey(
  // This must be a ImportKeyOptions<T>, and then unwrapKey returns Future<T>
  // This allows us to ensure:
  //   - Typing when specifying HMAC import parameters
  //   - Prevents the user from trying using SPKI with options belonging to
  //     a private RsaPssPrivateKey which doesn't support importSpkiKey(...)
  //
  // Note: I do not like the naming, I'd love something shorter, maybe just:
  //       HmacSecretKey.importJwkOptions or HmacSecretKey.importJwkParams
  HmacSecretKey.importJsonWebKeyOptions(Hash.sha256),
  wrappedKeyAsBytes,
  iv,
);

final hmacKey = await secretKey.unwrapKey(
  HmacSecretKey.importRawKeyOptions(Hash.sha256),
  wrappedKeyAsBytes,
  iv,
);

final hmacKey = await hkdfKey.deriveKey(
  // This must be a DeriveKeyOptions<T>, and then deriveKey returns Future<T>
  // This allows us to limit what keys can be derived, webcrypto can only derive
  // HMAC, AES-CBC, AES-CTR, AES-GCM and AES-KW.
  //
  // This is almost the same as ImportKeyOptions, except not all algorithms
  // support being derived, only things that can be imported from raw.
  // And even then, not all key types that can be imported from raw!
  HmacSecretKey.deriveKeyOptions(Hash.sha256),
  salt,
  info,
);

@sealed
abstract class WrapKeyInput {} // Could also be called WrappableKey

@sealed
abstract class ImportKeyOptions<T> {} // Could also be called WrappedKeyOptions

@sealed
abstract class DeriveKeyOptions<T> {}


// ---------------------------------------

// Same proposal as above, except we get rid of the <T> type parameterization!

// WARNING: This proposal has the problem that the VERB we're doing
//          such as wrap / unwrap / derive just returns an <..>Options object
//          instead of returning a Future and actually doing the work.
//          This might give the wrong impression of what object is doing the work.

final hmacKey = await HmacSecretKey.generate(Hash.sha256);

final wrappedKeyAsBytes await = hmacKey.exportWrappedRawKey(
  // WrapKeyOptions
  secretKey.wrapKeyOptions(iv),
);

final hmacKey = await HmacSecretKey.importWrappedJsonWebKey(
  // UnwrapKeyOptions
  secretKey.unwrapKeyOptions(iv),
  wrappedKeyAsBytes,
  Hash.sha256,
);

final hmacKey = await HmacSecretKey.importWrappedRawKey(
  secretKey.unwrapKeyOptions(iv),
  wrappedKeyAsBytes,
  Hash.sha256,
);

final hmacKey = await HmacSecretKey.importDerivedKey(
  // DeriveKeyOptions
  hkdfKey.deriveKeyOptions(salt, info),
);

// ERROR: The opaque objects are abstractions that invite the user to reuse
//        the object for unwrapping, wrapper or deriving many keys.
//        The user may get the idea that they creatae a single WrapKeyOptions
//        object, and use it to wrap a lot of keys.
//        THIS is EXTREMELY bad, because WrapKeyOptions holds iv and other things
//        that should be unique and unprediable for each operation.
//        Depending on the primitives, but reuse is generally unsafe.
//        So abstractions that creates an illusion that reuse is okay are BAD!
@sealed
abstract class WrapKeyOptions {} // Could also be called KeyWrapper

@sealed
abstract class UnwrapKeyOptions {} // Could also be called KeyUnwrapper

@sealed
abstract class DeriveKeyOptions {} // Could alos be called KeyDeriver



// ---------------------------------------

// I fear users will able to read documentation very backwards to get this working.
// It might type nicely, and it might look good in a draft..
final hmacKey = await HmacSecretKey.options(Hash.sha256).generate();
final hmacKey = await HmacSecretKey.options(Hash.sha256).raw.import(...);
final hmacKey = await HmacSecretKey.options(Hash.sha256).jwk.import(...);

final wrappedKeyAsBytes = await secretKey.wrapJsonWebKey(hmacKey, iv);

final hmacKey = await secretKey.unwrapKey(
  // KeyImportOptions
  HmacSecretKey.options(Hash.sha256).jwk,
  wrappedKeyAsBytes,
  iv,
);

final hmacKey = await hkdfKey.deriveKey(
  // Only allows KeyImportRawOrDeriveOptions, which only keys that support
  // being derived can create.
  HmacSecretKey.options(Hash.sha256).raw,
  salt,
  info,
);

// ERROR: THis makes NO SENSE... Sorry!!!

@sealed
abstract class KeyOptions<T> {}

@sealed
abstract class KeyImportOptions<T> {}

abstract class KeyImportRawOptions<T> implements KeyImportOptions<T> {
  Future<T> import(List<int> keyData);
}

abstract class KeyImportRawOrDeriveOptions<T> implements KeyImportOptions<T> {
  Future<T> import(List<int> keyData);
}

abstract class KeyImportJwkOptions<T> implements KeyImportOptions<T> {
  Future<T> import(Map<String, dynamic> jwk);
}



// ---------------------------------------

final hmacKey = await HmacSecretKey.generate(Hash.sha256);


final wrappedKeyAsBytes = await secretKey.wrapKey(
  // this is a WrapKeyOptions -- just a way type key + format, ensuring you
  // can't use a format not supported for a given key.
  // Also weird to have a format enum, not used in import/export methods!
  hmacKey.wrapRawKeyOptions(),
  // options for encryptBytes, differs depending on secretKey type!
  iv,
);

final wrappedKeyAsBytes = await secretKey.wrapKey(
  hmacKey.wrapJsonWebKeyOptions(),
  iv,
);


final hmacKey = await secretKey.unwrapKey(
  // This is a UnwrapKeyOptions -- which is format + import options
  HmacSecretKey.unwrapJsonWebKeyOptions(Hash.sha256),
  wrappedKeyAsBytes,
  // options for decryptBytes, differs depending on secretKey type
  iv,
);

final hmacKey = await secretKey.unwrapKey(
  HmacSecretKey.unwrapRawKeyOptions(Hash.sha256),
  wrappedKeyAsBytes,
  iv,
);


final hmacKey = await hkdfKey.deriveKey(
  // This must be a DeriveKeyOptions<T>, and then deriveKey returns Future<T>
  // This allows us to limit what keys can be derived, webcrypto can only derive
  // HMAC, AES-CBC, AES-CTR, AES-GCM and AES-KW.
  HmacSecretKey.deriveKeyOptions(Hash.sha256),
  salt,
  info,
);

@sealed
abstract class WrapKeyOptions {}

@sealed
abstract class UnwrapKeyOptions<T> {}

@sealed
abstract class DeriveKeyOptions<T> {}

```
Note: if you need to do "key_ops" and "use" validation (which you might need to)
then look at the chrome implementation here:
https://source.chromium.org/chromium/chromium/src/+/main:components/webcrypto/j
