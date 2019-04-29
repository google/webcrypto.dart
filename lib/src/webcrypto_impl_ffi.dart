import 'dart:typed_data';
import '../webcrypto.dart';
import 'exceptions.dart';
import 'dart:math' as math;
import 'dart:async' show FutureOr;
import 'dart:ffi' as ffi;
import 'dart:convert' show utf8;
import 'boringssl_ffi/boringssl_ffi.dart' as ssl;

/// Throw [OperationError] or [DataException] if [condition] is `false`.
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
    final err = _extractError();
    message ??= err ?? fallback ?? 'unknown error';
    if (data) {
      throw dataException(message);
    }
    throw operationError(message);
  }
}

/// Extract latest error on this thread as [String] and clear the error queue
/// for this thread.
///
/// Returns `null` if there is no error.
String _extractError() {
  try {
    // Get the error.
    final err = ssl.ERR_get_error();
    if (err == 0) {
      return null;
    }
    const N = 4096; // Max error message size
    final data = _withOutPointer(N, (ssl.Bytes p) {
      ssl.ERR_error_string_n(err, p, N);
    });
    // Take everything until '\0'
    return utf8.decode(data.takeWhile((i) => i != 0).toList());
  } finally {
    // Always clear error queue, so we continue
    ssl.ERR_clear_error();
  }
}

abstract class _CryptoKeyBase implements CryptoKey {
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
        // case KeyUsage.deriveKey:
        //   name = 'deriveKey';
        //   break;
        case KeyUsage.deriveBits:
          name = 'deriveBits';
          break;
        // case KeyUsage.wrapKey:
        //   name = 'wrapKey';
        //   break;
        // case KeyUsage.unwrapKey:
        //   name = 'unwrapKey';
        //   break;
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

/// Implementation of CryptoKeyPair.
class _CryptoKeyPair<S, T> implements CryptoKeyPair<S, T> {
  final S privateKey;
  final T publicKey;

  _CryptoKeyPair(this.privateKey, this.publicKey) {
    assert(privateKey != null, 'privateKey cannot be "null"');
    assert(publicKey != null, 'publicKey cannot be "null"');
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
    throw notSupportedException('HashAlgorithm not supported: $hash');
  }
  final md = MD();
  _check(md.address != 0, fallback: 'failed to instantiate hash algorithm');
  return md;
}

/// Copy bytes from [source] to [target].
void _copyToPointer(
  ffi.Pointer<ffi.Uint8> target,
  List<int> source, [
  int start = 0,
  int end,
]) {
  end ??= source.length;
  for (int i = start; i < end; i++) {
    target.elementAt(i).store(source[i]);
  }
}

/// Copy bytes from [source] to [target], relying on size from [target].
void _copyFromPointer(List<int> target, ffi.Pointer<ffi.Uint8> source) {
  for (int i = 0; i < target.length; i++) {
    target[i] = source.elementAt(i).load<int>();
  }
}

/// Invoke [fn] with pointer to count of [T] and release it when [fn] returns.
R _withAllocation<T extends ffi.NativeType, R>(
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

/// Load [data] into a [ffi.Pointer] of type [T] and call [fn], and free the
/// pointer when [fn] returns.
///
/// This is an auxiliary function for getting a [ffi.Pointer] representation of
/// an [Uint8List] without risk of memory leaks.
R _withDataAsPointer<T extends ffi.Pointer, R>(
    List<int> data, R Function(T) fn) {
  final p = ffi.allocate<ffi.Uint8>(count: data.length);
  try {
    _copyToPointer(p, data);
    return fn(p.cast<T>());
  } finally {
    p.free();
  }
}

/// Allocated a [size] bytes [ffi.Pointer] of type [T] and call [fn], and copy
/// the data from the pointer to an [Uint8List] when [fn] returns. Freeing the
/// pointer when [fn] returns.
///
/// This is an auxiliary function for getting data out of functions that takes
/// an output buffer.
Uint8List _withOutPointer<T extends ffi.Pointer>(
  int size,
  void Function(T) fn,
) {
  final p = ffi.allocate<ffi.Uint8>(count: size);
  try {
    fn(p.cast<T>());
    final result = Uint8List(size);
    _copyFromPointer(result, p);
    return result;
  } finally {
    p.free();
  }
}

/// Pipe bytes from [source] to [update] with [ctx], useful for streaming
/// algorithms. Notice that chunk size from [data] may be altered.
Future<void> _pipeToUpdate<T, S extends ffi.Pointer>(
  Stream<List<int>> source,
  T ctx,
  int Function(T, S, int) update,
) async {
  const maxChunk = 4096;
  final bytes = ffi.allocate<ffi.Uint8>(count: maxChunk);
  try {
    final ptr = bytes.cast<S>();
    await for (final data in source) {
      int offset = 0;
      while (offset < data.length) {
        final n = math.min(data.length - offset, maxChunk);
        _copyToPointer(bytes, data, offset, offset + n);
        _check(update(ctx, ptr, n) == 1);
        offset += n;
      }
    }
  } finally {
    bytes.free();
  }
}

/// Invoke [fn] with an [ssl.EVP_MD_CTX] that is free'd when [fn] returns.
Future<R> _withEVP_MD_CTX<R>(FutureOr<R> Function(ssl.EVP_MD_CTX) fn) async {
  final ctx = ssl.EVP_MD_CTX_new();
  _check(ctx.address != 0, fallback: 'allocation error');
  try {
    return await fn(ctx);
  } finally {
    ssl.EVP_MD_CTX_free(ctx);
  }
}

/// Invoke [fn] with [data] loaded into a [ssl.CBS].
///
/// Both the [ssl.CBS] and the [ssl.Bytes] pointer allocated will be released
/// when [fn] returns.
R _withDataAsCBS<R>(List<int> data, R Function(ssl.CBS) fn) {
  return _withDataAsPointer(data, (ssl.Bytes p) {
    final size = ssl.CBS.sizeOf();
    final cbs = ffi.allocate<ffi.Uint8>(count: size).cast<ssl.CBS>();
    ssl.CBS_init(cbs, p, data.length);
    try {
      return fn(cbs);
    } finally {
      cbs.free();
    }
  });
}

/// Call [fn] with an initialized [ssl.CBB] and return the result as
/// [Uint8List].
Uint8List _withOutCBB(void Function(ssl.CBB) fn) {
  final cbb = ffi.allocate<ffi.Uint8>(count: ssl.CBB.sizeOf()).cast<ssl.CBB>();
  try {
    ssl.CBB_zero(cbb);
    try {
      _check(ssl.CBB_init(cbb, 4096) == 1, fallback: 'allocation failure');
      fn(cbb);
      _check(ssl.CBB_flush(cbb) == 1);
      final bytes = ssl.CBB_data(cbb);
      final len = ssl.CBB_len(cbb);
      final result = Uint8List(len);
      _copyFromPointer(result, bytes);
      return result;
    } finally {
      ssl.CBB_cleanup(cbb);
    }
  } finally {
    cbb.free();
  }
}

//---------------------- Random Bytes

void getRandomValues(TypedData destination) {
  final dest = destination.buffer.asUint8List();
  final p = ffi.allocate<ffi.Uint8>(count: dest.length).cast<ssl.Bytes>();
  try {
    _check(ssl.RAND_bytes(p, dest.length) == 1);
    _copyFromPointer(dest, p);
  } finally {
    p.free();
  }
}

//---------------------- Hash Algorithms

Future<List<int>> digest({HashAlgorithm hash, Stream<List<int>> data}) async {
  return await _withEVP_MD_CTX((ctx) async {
    _check(ssl.EVP_DigestInit(ctx, _hash(hash)) == 1);
    await _pipeToUpdate(data, ctx, ssl.EVP_DigestUpdate);
    final size = ssl.EVP_MD_CTX_size(ctx);
    return _withOutPointer(size, (ssl.Bytes p) {
      _check(ssl.EVP_DigestFinal(ctx, p, null) == 1);
    });
  });
}

//---------------------- HMAC

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

Future<HmacSecretKey> hmacSecret_importJsonWebKey({
  Map<String, Object> jwk,
  bool extractable,
  List<KeyUsage> usages,
  HashAlgorithm hash,
  int length,
}) async {
  // As per [1] we must follow [2].
  // [1]: https://www.w3.org/TR/WebCryptoAPI/#hmac-operations
  // [2]: https://tools.ietf.org/html/rfc7518#section-6.4
  if (jwk['kty'] != 'oct') {
    throw dataException('JWK encoding of HMAC keys must have "kty" == "oct"');
  }
  // TODO: Finish this... validate contents of JWK following [2]...

  throw UnimplementedError('implementation not finished yet');
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
      _withDataAsPointer(_keyData, (ssl.Data p) {
        _check(ssl.HMAC_Init_ex(ctx, p, _keyData.length, _hash, null) == 1);
      });
      await _pipeToUpdate(data, ctx, ssl.HMAC_Update);

      final size = ssl.HMAC_size(ctx);
      _check(size > 0);
      return _withAllocation(1, (ffi.Pointer<ffi.Uint32> psize) async {
        psize.store(size);
        return _withOutPointer(size, (ssl.Bytes p) {
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
    return _withDataAsPointer(signature, (ssl.Data s) {
      return _withDataAsPointer(other, (ssl.Data o) {
        return ssl.CRYPTO_memcmp(s, o, other.length) == 0;
      });
    });
  }

  @override
  Future<List<int>> exportRawKey() async {
    _checkExtractable();
    return Uint8List.fromList(_keyData);
  }

  @override
  Future<Map<String, Object>> exportJsonWebKey() async {
    _checkExtractable();
    // TODO: implement exportJsonWebKey for HmacSecretKey
    throw UnimplementedError('implementation not finished yet');
  }
}

//---------------------- RSASSA_PKCS1_v1_5

Future<RsassaPkcs1V15PrivateKey> rsassaPkcs1V15PrivateKey_importPkcs8Key({
  List<int> keyData,
  bool extractable,
  List<KeyUsage> usages,
  HashAlgorithm hash,
}) async {
  final key = _withDataAsCBS(keyData, ssl.EVP_parse_private_key);
  _check(key.address != 0, fallback: 'unable to parse key', data: true);

  try {
    final rsa = ssl.EVP_PKEY_get0_RSA(key);
    _check(rsa.address != 0, fallback: 'key is not an RSA key', data: true);
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
  final key = _withDataAsCBS(keyData, ssl.EVP_parse_public_key);
  _check(key.address != 0, fallback: 'unable to parse key', data: true);

  try {
    final rsa = ssl.EVP_PKEY_get0_RSA(key);
    _check(rsa.address != 0, fallback: 'key is not an RSA key', data: true);
    _check(ssl.RSA_check_key(rsa) == 1, fallback: 'invalid key', data: true);

    return _RsassaPkcs1V15PublicKey(key, _hash(hash), extractable, usages);
  } on Object {
    // We only free key if an exception/error was thrown
    ssl.EVP_PKEY_free(key);
    rethrow;
  }
}

/// Invoke [fn] with a new [ssl.BIGNUM] instance that is free'd when [fn]
/// returns.
R _withBIGNUM<R>(R Function(ssl.BIGNUM) fn) {
  final bn = ssl.BN_new();
  _check(bn.address != 0, fallback: 'allocation failure');
  try {
    return fn(bn);
  } finally {
    ssl.BN_free(bn);
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
  // Sanity check for the modulusLength
  if (modulusLength < 256 || modulusLength > 16384) {
    throw notSupportedException(
      'modulusLength must between 256 and 16k, $modulusLength is not supported',
    );
  }
  if ((modulusLength % 8) != 0) {
    throw notSupportedException(
        'modulusLength: $modulusLength is not a multiple of 8');
  }

  // Limit publicExponent whitelist as in chromium:
  // https://chromium.googlesource.com/chromium/src/+/43d62c50b705f88c67b14539e91fd8fd017f70c4/components/webcrypto/algorithms/rsa.cc#286
  if (publicExponent != BigInt.from(3) &&
      publicExponent != BigInt.from(65537)) {
    throw notSupportedException(
        'publicExponent is not supported, try 3 or 65537');
  }

  ssl.RSA privRSA, pubRSA;
  ssl.EVP_PKEY privKey, pubKey;
  try {
    // Generate private RSA key
    privRSA = ssl.RSA_new();
    _check(privRSA.address != 0, fallback: 'allocation failure');
    _withBIGNUM((e) {
      _check(ssl.BN_set_word(e, publicExponent.toInt()) == 1);
      _check(ssl.RSA_generate_key_ex(privRSA, modulusLength, e, null) == 1);
    });

    // Copy out the public RSA key
    final pubRSA = ssl.RSAPublicKey_dup(privRSA);
    _check(pubRSA.address != 0);

    // Create private key
    privKey = ssl.EVP_PKEY_new();
    _check(privKey.address != 0, fallback: 'allocation failure');
    _check(ssl.EVP_PKEY_set1_RSA(privKey, privRSA) == 1);

    // Create public key
    pubKey = ssl.EVP_PKEY_new();
    _check(pubKey.address != 0, fallback: 'allocation failure');
    _check(ssl.EVP_PKEY_set1_RSA(pubKey, pubRSA) == 1);

    final md = _hash(hash);
    return _CryptoKeyPair(
      _RsassaPkcs1V15PrivateKey(
        privKey,
        md,
        extractable,
        usages.where([KeyUsage.sign].contains).toList(),
      ),
      _RsassaPkcs1V15PublicKey(
        pubKey,
        md,
        extractable,
        usages.where([KeyUsage.verify].contains).toList(),
      ),
    );
  } on Object {
    // Free privKey/pubKey on exception
    if (privKey != null) {
      ssl.EVP_PKEY_free(privKey);
    }
    if (pubKey != null) {
      ssl.EVP_PKEY_free(pubKey);
    }
    rethrow;
  } finally {
    // Always free RSA keys, we create a new reference with set1 method
    if (privRSA != null) {
      ssl.RSA_free(privRSA);
    }
    if (pubRSA != null) {
      ssl.RSA_free(pubRSA);
    }
  }
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

    return _withEVP_MD_CTX((ctx) async {
      _check(ssl.EVP_DigestSignInit(ctx, null, _hash, null, _key) == 1);
      await _pipeToUpdate(data, ctx, ssl.EVP_DigestSignUpdate);
      return _withAllocation(1, (ffi.Pointer<ffi.IntPtr> len) {
        len.store(0);
        _check(ssl.EVP_DigestSignFinal(ctx, null, len) == 1);
        return _withOutPointer(len.load<int>(), (ssl.Bytes p) {
          _check(ssl.EVP_DigestSignFinal(ctx, p, len) == 1);
        }).sublist(0, len.load<int>());
      });
    });
  }

  @override
  Future<List<int>> exportPkcs8Key() async {
    _checkExtractable();
    return _withOutCBB((cbb) {
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

    return _withEVP_MD_CTX((ctx) async {
      _check(ssl.EVP_DigestVerifyInit(ctx, null, _hash, null, _key) == 1);
      await _pipeToUpdate(data, ctx, ssl.EVP_DigestVerifyUpdate);
      return _withDataAsPointer(signature, (ssl.Bytes p) {
        final result = ssl.EVP_DigestVerifyFinal(ctx, p, signature.length);
        return result == 1;
      });
    });
  }

  @override
  Future<List<int>> exportSpkiKey() async {
    _checkExtractable();
    return _withOutCBB((cbb) {
      _check(ssl.EVP_marshal_public_key(cbb, _key) == 1);
    });
  }
}
