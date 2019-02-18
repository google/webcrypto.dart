import 'dart:typed_data';
import '../webcrypto.dart';
import 'dart:async' show FutureOr;
import 'dart:ffi' as ffi;
import 'boringssl_ffi/boringssl_ffi.dart' as ssl;

final _notImplemented = UnimplementedError(
  'webcrypto not availble on this platform',
);

/// Throw [OperationException] or [DataException] if [condition] is `false`.
///
/// If [message] is given we use that, otherwise we use error from BoringSSL,
/// and if nothing is available there we use [fallback].
void _check(
  bool condition, {
  String message,
  String fallback,
  bool data = false,
}) {
  if (!condition) {
    // Always extract the error to ensure we clear the error queue.
    final err = ssl.extractError();
    message ??= err ?? fallback ?? 'unknown error';
    if (data) {
      throw DataException(message);
    }
    throw OperationException(message);
  }
}

abstract class _CryptoKeyBase extends CryptoKey {
  final bool extractable;
  final List<KeyUsage> usages;
  _CryptoKeyBase(this.extractable, this.usages) {
    // Verify invariants that should be checked other places.
    assert(extractable != null);
    assert(usages != null);
  }

  void _checkUsage(KeyUsage usage) {
    if (!usages.contains(usage)) {
      String name;
      switch (usage) {
        case KeyUsage.encrypt:
          name = 'encrypt';
          break;
        case KeyUsage.decrypt:
          name = 'decrypt';
          break;
        case KeyUsage.sign:
          name = 'sign';
          break;
        case KeyUsage.verify:
          name = 'verify';
          break;
        case KeyUsage.deriveKey:
          name = 'deriveKey';
          break;
        case KeyUsage.deriveBits:
          name = 'deriveBits';
          break;
        case KeyUsage.wrapKey:
          name = 'wrapKey';
          break;
        case KeyUsage.unwrapKey:
          name = 'unwrapKey';
          break;
      }
      assert(name != null, 'unknown KeyUsage');
      if (name == null) {
        name = 'unknown';
      }
      throw StateError(
        'operation forbidding, the key was not created with `KeyUsage.$name`',
      );
    }
  }

  void _checkExtractable() {
    if (!extractable) {
      throw StateError(
          'key cannot be extracted, when created with `extractable = false`');
    }
  }
}

final _hashAlgorithms = {
  HashAlgorithm.sha1: ssl.EVP_sha1,
  HashAlgorithm.sha256: ssl.EVP_sha256,
  HashAlgorithm.sha384: ssl.EVP_sha384,
  HashAlgorithm.sha512: ssl.EVP_sha512,
};

/// Get EVP_MD for [hash].
ssl.EVP_MD _hash(HashAlgorithm hash) {
  final MD = _hashAlgorithms[hash];
  if (MD == null) {
    throw NotSupportedException('HashAlgorithm not supported: $hash');
  }
  final md = MD();
  _check(md.address != 0);
  return md;
}

// TODO: Move all the with... methods in here, and make every Future-proof

/// Invoke [fn] with a newly allocated [ssl.EVP_MD_CTX] and release it when
/// [fn] returns.
Future<R> withEVP_MD_CTX<R>(FutureOr<R> Function(ssl.EVP_MD_CTX) fn) async {
  final ctx = ssl.EVP_MD_CTX_new();
  _check(ctx.address != 0, fallback: 'allocation error');
  try {
    return await fn(ctx);
  } finally {
    ssl.EVP_MD_CTX_free(ctx);
  }
}

/// Invoke [fn] with pointer to count of [T] and release it when [fn] returns.
R withAllocate<T extends ffi.NativeType, R>(
  int count,
  R Function(ffi.Pointer<T>) fn,
) {
  final p = ffi.allocate<T>(count: count);
  try {
    return fn(p);
  } finally {
    p.free();
  }
}

///////////////////////////// Random Bytes

void getRandomValues(TypedData destination) {
  final dest = destination.buffer.asUint8List();
  final p = ffi.allocate<ffi.Uint8>(count: dest.length).cast<ssl.Bytes>();
  try {
    _check(ssl.RAND_bytes(p, dest.length) == 1);
    for (int i = 0; i < dest.length; i++) {
      dest[i] = p.elementAt(i).load<int>();
    }
  } finally {
    p.free();
  }
}

///////////////////////////// Hash Algorithms

Future<List<int>> digest({HashAlgorithm hash, Stream<List<int>> data}) async {
  return withEVP_MD_CTX((ctx) async {
    _check(ssl.EVP_DigestInit(ctx, _hash(hash)) == 1);
    await for (final chunk in data) {
      ssl.withInputPointer(chunk, (ssl.Data p) {
        _check(ssl.EVP_DigestUpdate(ctx, p, chunk.length) == 1);
      });
    }
    final size = ssl.EVP_MD_CTX_size(ctx);
    _check(size > 0);
    return ssl.withOutputPointer(size, (ssl.Bytes p) {
      _check(ssl.EVP_DigestFinal(ctx, p, null) == 1);
    });
  });
}

///////////////////////////// HMAC

/// Convert [data] to [Uint8List] and zero to [lengthInBits] if given.
Uint8List _asUint8ListZeroedToBitLength(List<int> data, [int lengthInBits]) {
  data = Uint8List.fromList(data);
  if (lengthInBits != null) {
    final startFrom = (lengthInBits / 8).floor();
    int remainder = (lengthInBits % 8).toInt();
    for (int i = startFrom; i < data.length; i++) {
      // TODO: This passes tests, but I think this should be >> instead.. hmm...
      final mask = 0xff & (0xff << (8 - remainder));
      data[i] = data[i] & mask;
      remainder = 8;
    }
  }
  return data;
}

Future<HmacSecretKey> hmacSecret_importRawKey({
  List<int> keyData,
  bool extractable,
  List<KeyUsage> usages,
  HashAlgorithm hash,
  int length,
}) async {
  return _HmacSecretKey(
    _hash(hash),
    _asUint8ListZeroedToBitLength(keyData, length),
    extractable,
    usages,
  );
}

Future<HmacSecretKey> hmacSecret_generateKey({
  bool extractable,
  List<KeyUsage> usages,
  HashAlgorithm hash,
  int length,
}) async {
  length ??= ssl.EVP_MD_size(_hash(hash)) * 8;
  final keyData = Uint8List((length / 8).ceil());
  getRandomValues(keyData);

  return _HmacSecretKey(
    _hash(hash),
    _asUint8ListZeroedToBitLength(keyData, length),
    extractable,
    usages,
  );
}

class _HmacSecretKey extends _CryptoKeyBase implements HmacSecretKey {
  final ssl.EVP_MD _hash;
  final Uint8List _keyData;

  _HmacSecretKey(this._hash, this._keyData, extractable, List<KeyUsage> usages)
      : super(extractable, usages);

  Future<Uint8List> _sign(Stream<List<int>> data) async {
    final ctx = ssl.HMAC_CTX_new();
    _check(ctx.address != 0, fallback: 'allocation error');
    try {
      ssl.withInputPointer(_keyData, (ssl.Data p) {
        _check(ssl.HMAC_Init_ex(ctx, p, _keyData.length, _hash, null) == 1);
      });
      await for (final chunk in data) {
        ssl.withInputPointer(chunk, (ssl.Bytes p) {
          _check(ssl.HMAC_Update(ctx, p, chunk.length) == 1);
        });
      }

      final size = ssl.HMAC_size(ctx);
      _check(size > 0);
      return await withAllocate(1, (ffi.Pointer<ffi.Uint32> psize) async {
        psize.store(size);
        return ssl.withOutputPointer(size, (ssl.Bytes p) {
          _check(ssl.HMAC_Final(ctx, p, psize) == 1);
        }).sublist(0, psize.load<int>());
      });
    } finally {
      ssl.HMAC_CTX_free(ctx);
    }
  }

  @override
  Future<List<int>> sign({Stream<List<int>> data}) async {
    _checkUsage(KeyUsage.sign);
    return await _sign(data);
  }

  @override
  Future<bool> verify({List<int> signature, Stream<List<int>> data}) async {
    _checkUsage(KeyUsage.verify);

    final other = await _sign(data);
    if (signature.length != other.length) {
      return false;
    }
    return ssl.withInputPointer(signature, (ssl.Data s) {
      return ssl.withInputPointer(other, (ssl.Data o) {
        return ssl.CRYPTO_memcmp(s, o, other.length) == 0;
      });
    });
  }

  @override
  Future<List<int>> exportRawKey() async {
    _checkExtractable();
    return Uint8List.fromList(_keyData);
  }
}

///////////////////////////// RSASSA_PKCS1_v1_5

Future<RsassaPkcs1V15PrivateKey> rsassaPkcs1V15PrivateKey_importPkcs8Key({
  List<int> keyData,
  bool extractable,
  List<KeyUsage> usages,
  HashAlgorithm hash,
}) async {
  final key = ssl.withInputCBS(keyData, (cbs) {
    return ssl.EVP_parse_private_key(cbs);
  });
  _check(key.address == 0, fallback: 'unable to parse key', data: true);

  try {
    final rsa = ssl.EVP_PKEY_get0_RSA(key);
    _check(rsa.address == 0, fallback: 'key is not an RSA key', data: true);
    _check(ssl.RSA_check_key(rsa) == 1, fallback: 'invalid key', data: true);

    return _RsassaPkcs1V15PrivateKey(key, _hash(hash), extractable, usages);
  } on Object {
    // We only free key if an exception/error was thrown
    ssl.EVP_PKEY_free(key);
    rethrow;
  }
}

Future<RsassaPkcs1V15PublicKey> rsassaPkcs1V15PublicKey_importSpkiKey({
  List<int> keyData,
  bool extractable,
  List<KeyUsage> usages,
  HashAlgorithm hash,
}) async {
  final key = ssl.withInputCBS(keyData, (cbs) {
    return ssl.EVP_parse_public_key(cbs);
  });
  _check(key.address == 0, fallback: 'unable to parse key', data: true);

  try {
    final rsa = ssl.EVP_PKEY_get0_RSA(key);
    _check(rsa.address == 0, fallback: 'key is not an RSA key', data: true);
    _check(ssl.RSA_check_key(rsa) == 1, fallback: 'invalid key', data: true);

    return _RsassaPkcs1V15PublicKey(key, _hash(hash), extractable, usages);
  } on Object {
    // We only free key if an exception/error was thrown
    ssl.EVP_PKEY_free(key);
    rethrow;
  }
}

Future<CryptoKeyPair<RsassaPkcs1V15PrivateKey, RsassaPkcs1V15PublicKey>>
    rsassaPkcs1V15PrivateKey_generateKey({
  int modulusLength,
  BigInt publicExponent,
  HashAlgorithm hash,
  bool extractable,
  List<KeyUsage> usages,
}) async {
  throw _notImplemented;
}

class _RsassaPkcs1V15PrivateKey extends _CryptoKeyBase
    implements RsassaPkcs1V15PrivateKey {
  final ssl.EVP_PKEY _key;
  final ssl.EVP_MD _hash;

  _RsassaPkcs1V15PrivateKey(
    this._key,
    this._hash,
    extractable,
    List<KeyUsage> usages,
  ) : super(extractable, usages);

  void _finalize() {
    // TODO: implement finalizer, when supported in dart:ffi
    ssl.EVP_PKEY_free(_key);
  }

  @override
  Future<List<int>> sign({Stream<List<int>> data}) {
    ArgumentError.checkNotNull(data, 'data');
    _checkUsage(KeyUsage.sign);

    return withEVP_MD_CTX((ctx) async {
      _check(ssl.EVP_DigestSignInit(ctx, null, _hash, null, _key) == 1);
      await for (final chunk in data) {
        ssl.withInputPointer(chunk, (ssl.Data p) {
          _check(ssl.EVP_DigestSignUpdate(ctx, p, chunk.length) == 1);
        });
      }
      return withAllocate(1, (ffi.Pointer<ffi.IntPtr> len) {
        len.store(0);
        _check(ssl.EVP_DigestSignFinal(ctx, null, len) == 1);
        return ssl.withOutputPointer(len.load<int>(), (ssl.Bytes p) {
          _check(ssl.EVP_DigestSignFinal(ctx, p, len) == 1);
        }).sublist(0, len.load<int>());
      });
    });
  }

  @override
  Future<List<int>> exportPkcs8Key() async {
    _checkExtractable();
    return ssl.withOutputCBB((cbb) {
      _check(ssl.EVP_marshal_private_key(cbb, _key) == 1);
    });
  }
}

class _RsassaPkcs1V15PublicKey extends _CryptoKeyBase
    implements RsassaPkcs1V15PublicKey {
  final ssl.EVP_PKEY _key;
  final ssl.EVP_MD _hash;

  _RsassaPkcs1V15PublicKey(
    this._key,
    this._hash,
    extractable,
    List<KeyUsage> usages,
  ) : super(extractable, usages);

  void _finalize() {
    // TODO: implement finalizer, when supported in dart:ffi
    ssl.EVP_PKEY_free(_key);
  }

  @override
  Future<bool> verify({List<int> signature, Stream<List<int>> data}) {
    ArgumentError.checkNotNull(signature, 'signature');
    ArgumentError.checkNotNull(data, 'data');
    _checkUsage(KeyUsage.verify);

    return withEVP_MD_CTX((ctx) async {
      _check(ssl.EVP_DigestVerifyInit(ctx, null, _hash, null, _key) == 1);
      await for (final chunk in data) {
        ssl.withInputPointer(chunk, (ssl.Data p) {
          _check(ssl.EVP_DigestVerifyUpdate(ctx, p, chunk.length) == 1);
        });
      }
      return ssl.withInputPointer(signature, (ssl.Bytes p) {
        final result = ssl.EVP_DigestVerifyFinal(ctx, p, signature.length);
        return result == 1;
      });
    });
  }

  @override
  Future<List<int>> exportSpkiKey() async {
    _checkExtractable();
    return ssl.withOutputCBB((cbb) {
      _check(ssl.EVP_marshal_public_key(cbb, _key) == 1);
    });
  }
}
