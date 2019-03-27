/// Outline of all classes **including those not implemented yet**.
///
/// See the `webcrypto.dart` library for classes that have been implemented with
/// both `dart:js` and `dart:ffi`.
library incomplete;

import 'dart:async';
import 'dart:typed_data';
import 'package:meta/meta.dart';
import 'src/utils.dart' show checkAllowedUsages, normalizeUsages;
import 'src/cryptokey.dart';
import 'webcrypto.dart';

export 'webcrypto.dart';

// TODO: Add exportJwk() to all CryptoKey types (I think everything supports this)
// TODO: Add exportRaw()/importRaw to ECDSA which also supports raw format.

abstract class RsaPssPrivateKey implements CryptoKey {
  RsaPssPrivateKey._(); // keep the constructor private.

  static Future<RsaPssPrivateKey> importPkcs8Key({
    @required List<int> keyData,
    @required HashAlgorithm hash,
    @required bool extractable,
    @required List<KeyUsage> usages,
  }) {
    ArgumentError.checkNotNull(keyData, 'keyData');
    ArgumentError.checkNotNull(extractable, 'extractable');
    checkAllowedUsages('RSA-PSS', usages, [KeyUsage.sign]);
    usages = normalizeUsages(usages);
    ArgumentError.checkNotNull(hash, 'hash');

    throw UnimplementedError('TODO: implement RSA-PSS');
  }

  static Future<CryptoKeyPair<RsaPssPrivateKey, RsaPssPublicKey>> generateKey({
    @required int modulusLength,
    @required BigInt publicExponent,
    @required HashAlgorithm hash,
    @required bool extractable,
    @required List<KeyUsage> usages,
  }) {
    ArgumentError.checkNotNull(modulusLength, 'modulusLength');
    ArgumentError.checkNotNull(publicExponent, 'publicExponent');
    ArgumentError.checkNotNull(hash, 'hash');
    ArgumentError.checkNotNull(extractable, 'extractable');
    checkAllowedUsages('RSA-PSS', usages, [
      KeyUsage.sign,
      KeyUsage.verify,
    ]);
    usages = normalizeUsages(usages);

    throw UnimplementedError('TODO: implement RSA-PSS');
  }

  Future<List<int>> sign({
    @required Stream<List<int>> data,
    @required int saltLength,
  });

  Future<List<int>> exportPkcs8Key();
}

abstract class RsaPssPublicKey implements CryptoKey {
  RsaPssPublicKey._(); // keep the constructor private.

  static Future<RsaPssPublicKey> importSpkiKey({
    @required List<int> keyData,
    @required HashAlgorithm hash,
    @required bool extractable,
    @required List<KeyUsage> usages,
  }) {
    ArgumentError.checkNotNull(keyData, 'keyData');
    ArgumentError.checkNotNull(extractable, 'extractable');
    checkAllowedUsages('RSA-PSS', usages, [KeyUsage.verify]);
    usages = normalizeUsages(usages);
    ArgumentError.checkNotNull(hash, 'hash');

    throw UnimplementedError('TODO: implement RSA-PSS');
  }

  Future<bool> verify({
    @required List<int> signature,
    @required Stream<List<int>> data,
    @required int saltLength,
  });

  Future<List<int>> exportSpkiKey();
}

enum EllipticCurve {
  p256,
  p384,
  p521,
}

abstract class EcdsaPrivateKey implements CryptoKey {
  EcdsaPrivateKey._(); // keep the constructor private.

  static Future<EcdsaPrivateKey> importPkcs8Key({
    @required List<int> keyData,
    @required EllipticCurve curve,
    @required bool extractable,
    @required List<KeyUsage> usages,
  }) {
    ArgumentError.checkNotNull(keyData, 'keyData');
    ArgumentError.checkNotNull(extractable, 'extractable');
    checkAllowedUsages('ECDSA', usages, [KeyUsage.sign]);
    usages = normalizeUsages(usages);
    ArgumentError.checkNotNull(curve, 'curve');

    throw UnimplementedError('TODO: implement ECDSA');
  }

  static Future<CryptoKeyPair<EcdsaPrivateKey, EcdsaPublicKey>> generateKey({
    @required EllipticCurve curve,
    @required bool extractable,
    @required List<KeyUsage> usages,
  }) {
    ArgumentError.checkNotNull(curve, 'curve');
    ArgumentError.checkNotNull(extractable, 'extractable');
    checkAllowedUsages('ECDSA', usages, [
      KeyUsage.sign,
      KeyUsage.verify,
    ]);
    usages = normalizeUsages(usages);

    throw UnimplementedError('TODO: implement ECDSA');
  }

  Future<List<int>> sign({
    @required Stream<List<int>> data,
    @required HashAlgorithm hash,
  });

  Future<List<int>> exportPkcs8Key();
}

abstract class EcdsaPublicKey implements CryptoKey {
  EcdsaPublicKey._(); // keep the constructor private.

  static Future<EcdsaPublicKey> importSpkiKey({
    @required List<int> keyData,
    @required EllipticCurve curve,
    @required bool extractable,
    @required List<KeyUsage> usages,
  }) {
    ArgumentError.checkNotNull(keyData, 'keyData');
    ArgumentError.checkNotNull(curve, 'curve');
    ArgumentError.checkNotNull(extractable, 'extractable');
    checkAllowedUsages('ECDSA', usages, [KeyUsage.verify]);
    usages = normalizeUsages(usages);

    throw UnimplementedError('TODO: implement ECDSA');
  }

  Future<bool> verify({
    @required List<int> signature,
    @required Stream<List<int>> data,
    @required HashAlgorithm hash,
  });

  Future<List<int>> exportSpkiKey();
}

abstract class RsaOaepPrivateKey implements CryptoKey {
  RsaOaepPrivateKey._(); // keep the constructor private.

  static Future<RsaOaepPrivateKey> importPkcs8Key({
    @required List<int> keyData,
    @required HashAlgorithm hash,
    @required bool extractable,
    @required List<KeyUsage> usages,
  }) {
    ArgumentError.checkNotNull(keyData, 'keyData');
    ArgumentError.checkNotNull(extractable, 'extractable');
    checkAllowedUsages('RSA-OAEP', usages, [
      KeyUsage.decrypt,
      KeyUsage.unwrapKey,
    ]);
    usages = normalizeUsages(usages);
    ArgumentError.checkNotNull(hash, 'hash');

    throw UnimplementedError('TODO: implement RSA-OAEP');
  }

  static Future<CryptoKeyPair<RsaOaepPrivateKey, RsaPssPublicKey>> generateKey({
    @required int modulusLength,
    @required BigInt publicExponent,
    @required HashAlgorithm hash,
    @required bool extractable,
    @required List<KeyUsage> usages,
  }) {
    ArgumentError.checkNotNull(modulusLength, 'modulusLength');
    ArgumentError.checkNotNull(publicExponent, 'publicExponent');
    ArgumentError.checkNotNull(hash, 'hash');
    ArgumentError.checkNotNull(extractable, 'extractable');
    checkAllowedUsages('RSA-OAEP', usages, [
      KeyUsage.decrypt,
      KeyUsage.unwrapKey,
      KeyUsage.encrypt,
      KeyUsage.wrapKey,
    ]);
    usages = normalizeUsages(usages);

    throw UnimplementedError('TODO: implement RSA-OAEP');
  }

  Stream<List<int>> decrypt({
    @required Stream<List<int>> data,
    TypedData label,
  });

  // TODO: add unwrapKey support

  Future<List<int>> exportPkcs8Key();
}

abstract class RsaOaepPublicKey implements CryptoKey {
  RsaOaepPublicKey._(); // keep the constructor private.

  static Future<RsaOaepPublicKey> importSpkiKey({
    @required List<int> keyData,
    @required HashAlgorithm hash,
    @required bool extractable,
    @required List<KeyUsage> usages,
  }) {
    ArgumentError.checkNotNull(keyData, 'keyData');
    ArgumentError.checkNotNull(extractable, 'extractable');
    checkAllowedUsages('RSA-OAEP', usages, [
      KeyUsage.encrypt,
      KeyUsage.wrapKey,
    ]);
    usages = normalizeUsages(usages);
    ArgumentError.checkNotNull(hash, 'hash');

    throw UnimplementedError('TODO: implement RSA-OAEP');
  }

  Stream<List<int>> encrypt({
    @required Stream<List<int>> data,
    TypedData label,
  });

  // TODO: add wrapKey support

  Future<List<int>> exportSpkiKey();
}

abstract class AesCtrSecretKey implements CryptoKey {
  AesCtrSecretKey._(); // keep the constructor private.

  static Future<AesCtrSecretKey> importRawKey({
    @required List<int> keyData,
    @required bool extractable,
    @required List<KeyUsage> usages,
  }) {
    ArgumentError.checkNotNull(keyData, 'keyData');
    ArgumentError.checkNotNull(extractable, 'extractable');
    checkAllowedUsages('AES-CTR', usages, [
      KeyUsage.encrypt,
      KeyUsage.decrypt,
      KeyUsage.wrapKey,
      KeyUsage.unwrapKey,
    ]);
    usages = normalizeUsages(usages);

    throw UnimplementedError('TODO: implement AES-CTR');
  }

  Stream<List<int>> encrypt({
    @required Stream<List<int>> data,
    @required TypedData counter,
    @required int length,
  });

  Stream<List<int>> decrypt({
    @required Stream<List<int>> data,
    @required TypedData counter,
    @required int length,
  });

  // TODO: add wrapKey support
  // TODO: add unwrapKey support

  Future<List<int>> exportRawKey();
}

abstract class AesCbcSecretKey implements CryptoKey {
  AesCbcSecretKey._(); // keep the constructor private.

  static Future<AesCbcSecretKey> importRawKey({
    @required List<int> keyData,
    @required bool extractable,
    @required List<KeyUsage> usages,
  }) {
    ArgumentError.checkNotNull(keyData, 'keyData');
    ArgumentError.checkNotNull(extractable, 'extractable');
    checkAllowedUsages('AES-CBC', usages, [
      KeyUsage.encrypt,
      KeyUsage.decrypt,
      KeyUsage.wrapKey,
      KeyUsage.unwrapKey,
    ]);
    usages = normalizeUsages(usages);

    throw UnimplementedError('TODO: implement AES-CBC');
  }

  Stream<List<int>> encrypt({
    @required Stream<List<int>> data,
    @required TypedData iv,
  });

  Stream<List<int>> decrypt({
    @required Stream<List<int>> data,
    @required TypedData iv,
  });

  // TODO: add wrapKey support
  // TODO: add unwrapKey support

  Future<List<int>> exportRawKey();
}

abstract class AesGcmSecretKey implements CryptoKey {
  AesGcmSecretKey._(); // keep the constructor private.

  static Future<AesGcmSecretKey> importRawKey({
    @required List<int> keyData,
    @required bool extractable,
    @required List<KeyUsage> usages,
  }) {
    ArgumentError.checkNotNull(keyData, 'keyData');
    ArgumentError.checkNotNull(extractable, 'extractable');
    checkAllowedUsages('AES-GCM', usages, [
      KeyUsage.encrypt,
      KeyUsage.decrypt,
      KeyUsage.wrapKey,
      KeyUsage.unwrapKey,
    ]);
    usages = normalizeUsages(usages);

    throw UnimplementedError('TODO: implement AES-GCM');
  }

  Stream<List<int>> encrypt({
    @required Stream<List<int>> data,
    @required TypedData iv,
    TypedData additionalData,
    int tagLength = 128,
  });

  Stream<List<int>> decrypt({
    @required Stream<List<int>> data,
    @required TypedData iv,
    TypedData additionalData,
    int tagLength = 128,
  });

  // TODO: add wrapKey support
  // TODO: add unwrapKey support

  Future<List<int>> exportRawKey();
}

abstract class AesKwSecretKey implements CryptoKey {
  AesKwSecretKey._(); // keep the constructor private.

  static Future<AesKwSecretKey> importRawKey({
    @required List<int> keyData,
    @required bool extractable,
    @required List<KeyUsage> usages,
  }) {
    ArgumentError.checkNotNull(keyData, 'keyData');
    ArgumentError.checkNotNull(extractable, 'extractable');
    checkAllowedUsages('AES-KW', usages, [
      KeyUsage.wrapKey,
      KeyUsage.unwrapKey,
    ]);
    usages = normalizeUsages(usages);

    throw UnimplementedError('TODO: implement AES-KW');
  }

  // TODO: add wrapKey support
  // TODO: add unwrapKey support

  Future<List<int>> exportRawKey();
}

abstract class EcdhPrivateKey implements CryptoKey {
  EcdhPrivateKey._(); // keep the constructor private.

  static Future<EcdhPrivateKey> importPkcs8Key({
    @required List<int> keyData,
    @required EllipticCurve curve,
    @required bool extractable,
    @required List<KeyUsage> usages,
  }) {
    ArgumentError.checkNotNull(keyData, 'keyData');
    ArgumentError.checkNotNull(extractable, 'extractable');
    checkAllowedUsages('ECDH', usages, [KeyUsage.sign]);
    usages = normalizeUsages(usages);
    ArgumentError.checkNotNull(curve, 'curve');

    throw UnimplementedError('TODO: implement ECDH');
  }

  static Future<CryptoKeyPair<EcdhPrivateKey, EcdhPublicKey>> generateKey({
    @required EllipticCurve curve,
    @required bool extractable,
    @required List<KeyUsage> usages,
  }) {
    ArgumentError.checkNotNull(curve, 'curve');
    ArgumentError.checkNotNull(extractable, 'extractable');
    checkAllowedUsages('ECDH', usages, [
      KeyUsage.deriveBits,
      KeyUsage.deriveKey,
    ]);
    usages = normalizeUsages(usages);

    throw UnimplementedError('TODO: implement ECDH');
  }

  Future<List<int>> deriveBits({
    @required EcdhPublicKey publicKey,
    @required int length,
  });

  // TODO: add deriveKey support

  Future<List<int>> exportPkcs8Key();
}

abstract class EcdhPublicKey implements CryptoKey {
  EcdhPublicKey._(); // keep the constructor private.

  static Future<EcdhPublicKey> importSpkiKey({
    @required List<int> keyData,
    @required EllipticCurve curve,
    @required bool extractable,
    @required List<KeyUsage> usages,
  }) {
    ArgumentError.checkNotNull(keyData, 'keyData');
    ArgumentError.checkNotNull(curve, 'curve');
    ArgumentError.checkNotNull(extractable, 'extractable');
    checkAllowedUsages('ECDH', usages, []);
    usages = normalizeUsages(usages);

    throw UnimplementedError('TODO: implement ECDH');
  }

  Future<List<int>> exportSpkiKey();
}

abstract class HkdfSecretKey implements CryptoKey {
  HkdfSecretKey._(); // keep the constructor private.

  static Future<HkdfSecretKey> importRawKey({
    @required List<int> keyData,
    @required List<KeyUsage> usages,
  }) {
    ArgumentError.checkNotNull(keyData, 'keyData');
    checkAllowedUsages('HKDF', usages, [
      KeyUsage.deriveBits,
      KeyUsage.deriveKey,
    ]);
    usages = normalizeUsages(usages);

    throw UnimplementedError('TODO: implement HKDF');
  }

  /// [HkdfSecretKey]'s can never be exported.
  @override
  bool get extractable => false;

  Future<List<int>> deriveBits({
    @required HashAlgorithm hash,
    @required TypedData salt,
    @required TypedData info,
  });

  // TODO: add deriveKey support
}

abstract class Pbkdf2SecretKey implements CryptoKey {
  Pbkdf2SecretKey._(); // keep the constructor private.

  static Future<Pbkdf2SecretKey> importRawKey({
    @required List<int> keyData,
    @required List<KeyUsage> usages,
  }) {
    ArgumentError.checkNotNull(keyData, 'keyData');
    checkAllowedUsages('PBKDF2', usages, [
      KeyUsage.deriveBits,
      KeyUsage.deriveKey,
    ]);
    usages = normalizeUsages(usages);

    throw UnimplementedError('TODO: implement PBKDF2');
  }

  /// [Pbkdf2SecretKey]'s can never be exported.
  @override
  bool get extractable => false;

  Future<List<int>> deriveBits({
    @required HashAlgorithm hash,
    @required TypedData salt,
    @required int iterations,
  });

  // TODO: add deriveKey support
}

// TODO: Figure out wrapKey/unwrapKey
/*

######### Option A) Don't support wrapKey/unwrapKey
Don't support wrapKey/unwrapKey, users who really wants it can just
encrypt/decrypt keys themselves. Only AES-KW supports wrap/unwrapKey without
also supporting encrypt/descript.

Downside is that this is actually quite nice to use in javascript world. It
allows for some really fancy crypto where a key is generated on the server and
wrapped, then unwrapped on the client in a manner that forbids the key from
being exported. All of this is obviously only hardening, and I doubt anyone
would go through all the hoops.

BIG DOWNSIDE: We lock outselves out of supporting wrapKey/unwrapKey using
option (B) in the future!!!

######### Option B) Introduce a KeyFormat enum
The bad/enum option:
  we create an enum for KeyFormat raw, pkcs8, spki, jwk
  Downside: export/import operations won't be typed, no import operations will
            support both pkcs8 and spki, none of the asymmetric supports raw.
            In few CryptoKey subclasses support more than one or two of the
            KeyFormats, so making it an enum seems hard to use.
            (And we're force to implement them all at once)

######### Option C) Introduce abstractions for KeyFormats

## wrapKey:
Could be done as:
  Future<List<int>> wrappingKey.wrapPkcs8Key({Pkcs8Key wrappedKey, ...encryptOptions});
This requires an abstraction to be made:
  abstract class Pkcs8ExportableKey {
    Future<List<int>> exportPkcs8Key();
  }
  class RsaPssPrivateKey implements CryptoKey, Pkcs8ExportableKey {...}

With this option we only get a method per KeyFormat, that's acceptable.
But we're forced to make an abstraction for each KeyFormat which seems useless.

## unwrapKey:
Could be done as:
  Future<T> wrappingKey.unwrapPkcs8Key<T>({UnwrapKeyOptions<T> wrappedKeyOptions, ...decryptOptions});
This requires an abstraction to be made:
  abstract class UnwrapKeyOptions<T extends CryptoKey> {
    // No public methods available.
  }
  class RsaPssPrivateKey implements CryptoKey, Pkcs8ExportableKey {
    static UnwrapKeyOptions<RsaPssPrivateKey> UnwrapOptions(key-specific-options);
  }

With this option you create a UnwrapKeyOptions<T> for the CryptoKey T you wish
to unwrap, then you pass that to the unwrap<KeyFormat>Key method. This is a bit
magic, but the type-system affords us some comfort here.

######### Option D) Explode wrapKey/unwrapKey methods
class AesKwSecretKey implements CryptoKey {
  Future<List<int>> wrapRsaPssPrivateKeyAsJwk(RsaPssPrivateKey key, ...encryptOptions);
  Future<List<int>> wrapRsaPssPrivateKeyAsPkcs8(RsaPssPrivateKey key, ...encryptOptions);
  Future<RsaPssPrivateKey> unwrapKeyRsaPssPrivateKeyFromJwk(List<int> data, ...decryptOptions);
  Future<RsaPssPrivateKey> unwrapKeyRsaPssPrivateKeyFromPkcs8(List<int> data, ...decryptOptions);
}

This is pretty bad, it creates a method for each KeyFormat and CryptoKey type.
But much CryptoKey types only support 2 key formats, so where as option (B)
would create 16 methods, this will probably create about 32 methods for both
WrapKey and unwrapKey.

That's a lot... but only 2X worse than option (B).

######### Option E) Introduce WrapKeyParams/UnwrapKeyParams

  class AesKwSecretKey implements CryptoKey {
    Future<List<int>> wrapKey(WrapKeyParams key, ...encryptOptions);
    Future<T> unwrapKey<T>(UnwrapKeyParams<T> options, ...decryptOptions);
  }
  class RsaPssPrivateKey implements CryptoKey {
    WrapKeyParams wrapAsJwk()
    WrapKeyParams wrapAsPkcs8()
    static UnwrapKeyParams<RsaPssPrivateKey> unwrapFromJwkParams(...importOptions);
    static UnwrapKeyParams<RsaPssPrivateKey> unwrapFromPkcs8Params(...importOptions);
  }

  abstract class WrapKeyParams {}
  abstract class UnwrapKeyParams<T extends CryptoKey> {}

######### Option F) Introduce KeyOptions<T>

abstract class Pkcs8ExportableKey {
  Future<List<int>> exportPkcs8Key();
}
abstract class RawExportableKey {
  Future<List<int>> exportRawKey();
}
abstract class KeyOptions<T extends CryptoKey> {}

class AesKwSecretKey implements CryptoKey {
  Future<List<int>> wrapKeyPkcs8(Pkcs8ExportableKey key, ...encryptOptions);
  
  Future<T> unwrapKeyPkcs8<T>(KeyOptions<T> options, ...decryptOptions);
}

class RsaPssPrivateKey implements CryptoKey, Pkcs8ExportableKey {
  static KeyOptions<T> keyOptions(...importOptions);
}

Downside:
  The `<KeyFormat>ExportableKey` abstraction seems a bit weird.
  It's not obvious that RsaPssPrivateKey.keyOptions can't be used with the
  raw key format. But then again, you can't export it as raw, so why would you
  every try to import it from raw -- there is no raw format.
Upsides:
  This also works for derive key.. which also needs KeyOptions<T>
  (though maybe we shouldn't only HMAC + AES can be derived with deriveKey)

######### Option G) Introduce KeyOptions<T> and KeyFormat enum

enum KeyFormat {raw, pkcs8, spki, jwk}

abstract class CryptoKey {
  ... // what it currently has

  Future<List<int>> exportKey(KeyFormat format);
}

abstract class KeyOptions<T extends CryptoKey> {}

Future<T> importKey<T extends CryptoKey>({
  @required List<int> data,
  required KeyOptions<T> options,
}) {...}

class RsaPssPrivateKey implements CryptoKey, Pkcs8ExportableKey {
  static KeyOptions<T> keyOptions(...importOptions);
}

class AesKwSecretKey implements CryptoKey {
  Future<List<int>> wrapKey(KeyFormat format, CryptoKey key, ...encryptOptions);
  
  Future<T> unwrapKey<T extends CryptoKey>({
    @required KeyFormat format,
    @required List<int> data,
    @required KeyOptions<T> options,
    ...decryptOptions, // AES-KW specific options
  });
}

Downside:
  * None if the CryptoKey subclasses supports all KeyFormats, typically 2-3
    formats are supported (spki makes no sense for a private key, RSA has no raw
    format, etc). You'll have to deduce this from API docs, which can say what
    key formats is supported by the given CryptoKey subclass.
  * In the browser export('jwk', ...) returns a JSON object, we would have to
    serialize that to utf-8 list of bytes for the method signature to work.
  * KeyOptions<T> has no-members and cannot be implemented by end-users, it's
    sort of a magic object, that carries options between two black boxes.
  * deriveKey can only use KeyOptions<T> for AES and HMAC CryptoKey types.
    Again this is not evident from the type-system.
Upside:
  * importKey now becomes a global function, instead of a static function on
    each CryptoKey subclass.
  * KeyOptions<T> can be used for importKey, unwrapKey, deriveKey, that's nice!!


######### Option H) Introduce UnwrapKeyOptions // TODO: Better name

The basic idea in this solution is that a CryptoKey that can wrap/unwrap another
key can create an opaque intermediate object called WrapKeyOptions/... this
object is then passed to an instance method or static function on the CryptoKey
class you wish to wrap/unwrap. Similarly, for deriveKey, the key used for
deriving another key would create an DeriveKeyOptions object, which would be
passed to a static deriveKey method on CryptoKey class you wish to derive.

**Example** when creating the intermediate UnwrapKeyOptions object the 
decryption options specific to the CryptoKey being used to unwrap with will be
specified. In the instance method for unwrap<KeyFormat>Key on the CryptoKey
class being decrypted, we shall specify the import options necessary. And the
unwrap<KeyFormat>Key will only be available for KeyFormat supported by the
given CryptoKey type.

// TODO: Better names for these abstractions (Options, Params, Encrypter,
         Wrapper, Box?, Operator, Operation, Vault, Locker, Handle, Seal,
         Envelope, Source)
         - KeyDerivationSource
         - KeyUnwrapParams
         - KeyUnwrapOperation
         - KeyEncrypter
         - WrappingKeyOptions / UnwrappingKeyOptions / DerivingKeyOptions
           (boring, but reasonable understandable...)
// TODO: the direction can also be flipped as done in Option (E), though this requires
         type parameters, which makes it all seem even more magic.

abstract class WrapKeyOptions {}   // Maybe call it KeyEncrypter
abstract class UnwrapKeyOptions {} // KeyDecrypter?


class AesKwSecretKey implements CryptoKey {
  WrapKeyOptions wrapKeyOptions(...encryptOptions);
  UnwrapKeyOptions unwrapKeyOptions(...decryptOptions);
}

class RsaPssPrivateKey implements CryptoKey {
  static Future<RsaPssPrivateKey> unwrapKeyPkcs8(
    @required UnwrapKeyOptions unwrapper, // key that unwraps
    @required List<int> data,
    ...importOptions, // import options for RsaPssPrivateKey
  );

  Future<List<int>> wrapKeyPkcs8(WrapKeyOptions options);
}

Downside:
1) WrapKeyOptions/... have no members and cannot be implemented by
   end-users, they are merely magic objects that carry options between two black
   boxes. You cannot interact with them, or try to understand them.
2) It's unnatural the an operation that uses encrypt/decrypt on AesKwSecretKey
   is located on the key that is encrypted/decrypted, rather than the key that
   does the encryption/decryption.
Upside:
 * Similar concept can be used for deriveKey, and CryptoKey types that can't be
   derived just doesn't feature a static deriveKey function.
 * You can't wrap/unwrap a key in a format that isn't supported for the given
   CryptoKey subclass. Methods for this isn't supported.
 * Methods to export key as JWK can return a JSON object, as they do in JS world.
 * We don't need to support for all key-formats at once, we can just add the
   methods later.

Note:
  Any solution that doesn't see AesKwSecretKey having a WrapKey/UnwrapKey method
  for each CryptoKey subclass (and there is 16), will have to have some magic
  object that carries options between two black boxes, downside (1). Hence, I
  see no way to avoid (1), no matter what design we pick.

  Downside (2) is unfortunate, maybe if we call the intermediate object
  something neat that indicates that it's a key to lock/unlock a wrapped key,
  this will be less scary.

  Note. in this design we still have a wrapKey/unwrapKey method for each
  CryptoKey subclass and each supported key format (2-3 depending on algorithm).
  There is 16 CryptoKey subclasses, so this is in the range of 34 methods.
  However, they will be located on the CryptoKey subclasses and not on
  every CryptoKey subclass that can be used to wrap/unwrap keys. This will
  typically add 2 static methods and 2 instances methods to each CryptoKey
  subclass (3 in the case of ECDSA, because it supports 3 key formats).

-----------------------------------------------------
Conclusion:
(not sure), but I really hate option (B) because it introduces another enum.
And because it makes it hard to know which KeyFormats are supported when
exporting a key, however, this can easily be documented in API docs, similar to
how we document which KeyUsages are supported for a given CryptoKey.

I suspect my dislike of this option is clouding my vision to the fact that this
is clearly the simplest and dumbest option. The least surprising and least magic
option. Option (C) is too clever, and cryptography APIs should probably not be
designed by people who are too clever for their own good! :)

Note. I'm now realizing that option (B) still requires us to have an UnwrapKey
method for each CryptoKey type and there is at-least 16 CryptoKey subclasses,
so that's not desireable. If we go with option (E) or (C) we create two methods.
And each CryptoKey will have 2-4 methods to create WrapKeyParams and
UnwrapKeyParams<T> types...

Fine, now I'm finally leaning towards option (H).

*/
