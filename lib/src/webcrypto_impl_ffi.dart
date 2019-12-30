import 'dart:async';
import 'dart:typed_data';
import 'dart:convert' show utf8;
import 'dart:ffi' as ffi;
import 'dart:math' as math;
import 'package:ffi/ffi.dart' as ffi;
import 'package:meta/meta.dart';

import '../webcrypto.dart';
import 'boringssl/boringssl.dart' as ssl;

final _notImplemented = throw UnimplementedError('Not implemented');

//---------------------- Helpers

/// Throw [OperationError] if [condition] is `false`.
///
/// If [message] is given we use that, otherwise we use error from BoringSSL,
/// and if nothing is available there we use [fallback].
void _checkOp(bool condition, {String message, String fallback}) {
  if (!condition) {
    // Always extract the error to ensure we clear the error queue.
    final err = _extractError();
    message ??= err ?? fallback ?? 'unknown error';
    throw _OperationError(message);
  }
}

/// Throw [OperationError] if [retval] is not `1`.
///
/// If [message] is given we use that, otherwise we use error from BoringSSL,
/// and if nothing is available there we use [fallback].
void _checkOpIsOne(int retval, {String message, String fallback}) =>
    _checkOp(retval == 1, message: message, fallback: fallback);

/// Throw [FormatException] if [condition] is `false`.
///
/// If [message] is given we use that, otherwise we use error from BoringSSL,
/// and if nothing is available there we use [fallback].
void _checkData(bool condition, {String message, String fallback}) {
  if (!condition) {
    // Always extract the error to ensure we clear the error queue.
    final err = _extractError();
    message ??= err ?? fallback ?? 'unknown error';
    throw FormatException(message);
  }
}

/// Throw [FormatException] if [retval] is `1`.
///
/// If [message] is given we use that, otherwise we use error from BoringSSL,
/// and if nothing is available there we use [fallback].
void _checkDataIsOne(int retval, {String message, String fallback}) =>
    _checkData(retval == 1, message: message, fallback: fallback);

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
    final data = _withOutPointer(N, (ffi.Pointer<ssl.Bytes> p) {
      ssl.ERR_error_string_n(err, p, N);
    });
    // Take everything until '\0'
    return utf8.decode(data.takeWhile((i) => i != 0).toList());
  } finally {
    // Always clear error queue, so we continue
    ssl.ERR_clear_error();
  }
}

/// Invoke [fn] with [ffi.Pointer<T>] of size count and release the pointer
/// when [fn] returns.
R _withAllocation<T extends ffi.NativeType, R>(
  int count,
  R Function(ffi.Pointer<T>) fn,
) {
  assert(!(R is Future), 'avoid async blocks');
  final p = ffi.allocate<T>(count: count);
  try {
    return fn(p);
  } finally {
    ffi.free(p);
  }
}

/// Invoke [fn] with [ffi.Pointer<T>] of size count and release the pointer
/// when future returned by [fn] completes.
Future<R> _withAllocationAsync<T extends ffi.NativeType, R>(
  int count,
  FutureOr<R> Function(ffi.Pointer<T>) fn,
) async {
  assert(!(R is Future), 'avoid nested async blocks');
  final p = ffi.allocate<T>(count: count);
  try {
    return await fn(p);
  } finally {
    ffi.free(p);
  }
}

/// Allocated a [size] bytes [ffi.Pointer<T>] and call [fn], and copy the data
/// from the pointer to an [Uint8List] when [fn] returns. Freeing the pointer
/// when [fn] returns.
///
/// This is an auxiliary function for getting data out of functions that takes
/// an output buffer.
Uint8List _withOutPointer<T extends ffi.NativeType>(
  int size,
  void Function(ffi.Pointer<T>) fn,
) {
  return _withAllocation(size, (ffi.Pointer<ffi.Uint8> p) {
    fn(p.cast<T>());
    return Uint8List.fromList(p.asTypedList(size));
  });
}

/// Load [data] into a [ffi.Pointer<T>], call [fn], and free the pointer when
/// [fn] returns.
///
/// This is an auxiliary function for getting a [ffi.Pointer] representation of
/// an [Uint8List] without risk of memory leaks.
R _withDataAsPointer<T extends ffi.NativeType, R>(
  List<int> data,
  R Function(ffi.Pointer<T>) fn,
) {
  return _withAllocation(data.length, (ffi.Pointer<ffi.Uint8> p) {
    p.asTypedList(data.length).setAll(0, data);
    return fn(p.cast<T>());
  });
}

/// Invoke [fn] with an [ffi.Pointer<ssl.EVP_MD_CTX>] that is free'd when
/// [fn] returns.
Future<R> _withEVP_MD_CTX<R>(
  FutureOr<R> Function(ffi.Pointer<ssl.EVP_MD_CTX>) fn,
) async {
  final ctx = ssl.EVP_MD_CTX_new();
  _checkOp(ctx.address != 0, fallback: 'allocation error');
  try {
    return await fn(ctx);
  } finally {
    ssl.EVP_MD_CTX_free(ctx);
  }
}

/// Invoke [fn] with an [ffi.Pointer<ffi.Pointer<ssl.EVP_PKEY_CTX>>] that is
/// free'd when [fn] returns.
Future<R> _withPEVP_PKEY_CTX<R>(
  FutureOr<R> Function(ffi.Pointer<ffi.Pointer<ssl.EVP_PKEY_CTX>> pctx) fn,
) =>
    _withAllocationAsync(1, fn);

/// Stream bytes from [source] to [update] with [ctx], useful for streaming
/// algorithms. Notice that chunk size from [data] may be altered.
Future<void> _streamToUpdate<T, S extends ffi.NativeType>(
  Stream<List<int>> source,
  T ctx,
  int Function(T, ffi.Pointer<S>, int) update,
) async {
  const maxChunk = 4096;
  final buffer = ffi.allocate<ffi.Uint8>(count: maxChunk);
  try {
    final ptr = buffer.cast<S>();
    final bytes = buffer.asTypedList(maxChunk);
    await for (final data in source) {
      int offset = 0;
      while (offset < data.length) {
        final N = math.min(data.length - offset, maxChunk);
        bytes.setAll(0, data.skip(offset).take(N));
        _checkOp(update(ctx, ptr, N) == 1);
        offset += N;
      }
    }
  } finally {
    ffi.free(buffer);
  }
}

/// Invoke [fn] with [data] loaded into a [ffi.Pointer<ssl.CBS>].
///
/// Both the [ssl.CBS] and the [ssl.Bytes] pointer allocated will be released
/// when [fn] returns.
R _withDataAsCBS<R>(List<int> data, R Function(ffi.Pointer<ssl.CBS>) fn) {
  return _withDataAsPointer(data, (ffi.Pointer<ssl.Bytes> p) {
    return _withAllocation(1, (ffi.Pointer<ssl.CBS> cbs) {
      ssl.CBS_init(cbs, p, data.length);
      return fn(cbs);
    });
  });
}

/// Call [fn] with an initialized [ffi.Pointer<ssl.CBB>] and return the result
/// as [Uint8List].
Uint8List _withOutCBB(void Function(ffi.Pointer<ssl.CBB>) fn) {
  return _withAllocation(1, (ffi.Pointer<ssl.CBB> cbb) {
    ssl.CBB_zero(cbb);
    try {
      _checkOp(ssl.CBB_init(cbb, 4096) == 1, fallback: 'allocation failure');
      fn(cbb);
      _checkOp(ssl.CBB_flush(cbb) == 1);
      final bytes = ssl.CBB_data(cbb);
      final len = ssl.CBB_len(cbb);
      return Uint8List.fromList(bytes.cast<ffi.Uint8>().asTypedList(len));
    } finally {
      ssl.CBB_cleanup(cbb);
    }
  });
}

/// Invoke [fn] with a new [ffi.Pointer<ssl.BIGNUM>] instance that is released
/// when [fn] returns.
R _withBIGNUM<R>(R Function(ffi.Pointer<ssl.BIGNUM>) fn) {
  final bn = ssl.BN_new();
  _checkOp(bn.address != 0, fallback: 'allocation failure');
  try {
    return fn(bn);
  } finally {
    ssl.BN_free(bn);
  }
}

/// Mixin for classes that needs to be finalized.
abstract class _Disposable {
  // TODO: implement finalizer, when supported in dart:ffi

  @protected
  void _finalize();
}

//---------------------- Utilities

/// Implementation of [OperationError].
class _OperationError extends Error implements OperationError {
  final String _message;

  _OperationError(this._message);

  @override
  String toString() => _message;
}

/// Implementation of [KeyPair].
class _KeyPair<S, T> implements KeyPair<S, T> {
  final S privateKey;
  final T publicKey;
  _KeyPair({this.privateKey, this.publicKey});
}

/// Convert [Stream<List<int>>] to [Uint8List].
Future<Uint8List> _bufferStream(Stream<List<int>> data) async {
  ArgumentError.checkNotNull(data, 'data');
  final result = <int>[];
  // TODO: Make this allocation stuff smarter
  await for (var chunk in data) {
    result.addAll(chunk);
  }
  return Uint8List.fromList(result);
}

//---------------------- RSA Helpers

ffi.Pointer<ssl.EVP_PKEY> _importPkcs8RsaPrivateKey(List<int> keyData) {
  final key = _withDataAsCBS(keyData, ssl.EVP_parse_private_key);
  _checkData(key.address != 0, fallback: 'unable to parse key');

  try {
    _checkData(ssl.EVP_PKEY_id(key) == ssl.EVP_PKEY_RSA,
        message: 'key is not an RSA key');

    final rsa = ssl.EVP_PKEY_get0_RSA(key);
    _checkData(rsa.address != 0, fallback: 'key is not an RSA key');
    _checkData(ssl.RSA_check_key(rsa) == 1, fallback: 'invalid key');

    return key;
  } catch (_) {
    // We only free key if an exception/error was thrown
    ssl.EVP_PKEY_free(key);
    rethrow;
  }
}

ffi.Pointer<ssl.EVP_PKEY> _importSpkiRsaPublicKey(List<int> keyData) {
  final key = _withDataAsCBS(keyData, ssl.EVP_parse_public_key);
  _checkData(key.address != 0, fallback: 'unable to parse key');

  try {
    _checkData(ssl.EVP_PKEY_id(key) == ssl.EVP_PKEY_RSA,
        message: 'key is not an RSA key');

    final rsa = ssl.EVP_PKEY_get0_RSA(key);
    _checkData(rsa.address != 0, fallback: 'key is not an RSA key');
    _checkData(ssl.RSA_check_key(rsa) == 1, fallback: 'invalid key');

    return key;
  } catch (_) {
    // We only free key if an exception/error was thrown
    ssl.EVP_PKEY_free(key);
    rethrow;
  }
}

_KeyPair<ffi.Pointer<ssl.EVP_PKEY>, ffi.Pointer<ssl.EVP_PKEY>>
    _generateRsaKeyPair(
  int modulusLength,
  BigInt publicExponent,
) {
  // Sanity check for the modulusLength
  if (modulusLength < 256 || modulusLength > 16384) {
    throw UnsupportedError(
      'modulusLength must between 256 and 16k, $modulusLength is not supported',
    );
  }
  if ((modulusLength % 8) != 0) {
    throw UnsupportedError(
        'modulusLength: $modulusLength is not a multiple of 8');
  }

  // Limit publicExponent whitelist as in chromium:
  // https://chromium.googlesource.com/chromium/src/+/43d62c50b705f88c67b14539e91fd8fd017f70c4/components/webcrypto/algorithms/rsa.cc#286
  if (publicExponent != BigInt.from(3) &&
      publicExponent != BigInt.from(65537)) {
    throw UnsupportedError('publicExponent is not supported, try 3 or 65537');
  }

  ffi.Pointer<ssl.RSA> privRSA, pubRSA;
  ffi.Pointer<ssl.EVP_PKEY> privKey, pubKey;
  try {
    // Generate private RSA key
    privRSA = ssl.RSA_new();
    _checkOp(privRSA.address != 0, fallback: 'allocation failure');
    _withBIGNUM((e) {
      _checkOp(ssl.BN_set_word(e, publicExponent.toInt()) == 1);
      _checkOp(
          ssl.RSA_generate_key_ex(privRSA, modulusLength, e, ffi.nullptr) == 1);
    });

    // Copy out the public RSA key
    final pubRSA = ssl.RSAPublicKey_dup(privRSA);
    _checkOp(pubRSA.address != 0);

    // Create private key
    privKey = ssl.EVP_PKEY_new();
    _checkOp(privKey.address != 0, fallback: 'allocation failure');
    _checkOp(ssl.EVP_PKEY_set1_RSA(privKey, privRSA) == 1);

    // Create public key
    pubKey = ssl.EVP_PKEY_new();
    _checkOp(pubKey.address != 0, fallback: 'allocation failure');
    _checkOp(ssl.EVP_PKEY_set1_RSA(pubKey, pubRSA) == 1);

    return _KeyPair(
      privateKey: privKey,
      publicKey: pubKey,
    );
  } catch (_) {
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

//---------------------- Random Bytes

void fillRandomBytes(TypedData destination) {
  final dest = destination.buffer.asUint8List(
    destination.offsetInBytes,
    destination.lengthInBytes,
  );
  _withAllocation(dest.length, (ffi.Pointer<ffi.Uint8> p) {
    _checkOp(ssl.RAND_bytes(p.cast<ssl.Bytes>(), dest.length) == 1);
    dest.setAll(0, p.asTypedList(dest.length));
  });
}

//---------------------- Hash Algorithms

abstract class _Hash implements Hash {
  const _Hash();

  factory _Hash.fromHash(Hash hash) {
    ArgumentError.checkNotNull(hash, 'hash');

    if (hash is _Hash) {
      return hash;
    }
    throw ArgumentError.value(
      hash,
      'hash',
      'Custom implementations of Hash is not supported',
    );
  }

  @protected
  ffi.Pointer<ssl.EVP_MD> Function() get _algorithm;

  /// Get an instantiated [ssl.EVP_MD] for this hash algorithm.
  ffi.Pointer<ssl.EVP_MD> get MD {
    final md = _algorithm();
    _checkOp(md.address != 0, fallback: 'failed to instantiate hash algorithm');
    return md;
  }

  @override
  Future<Uint8List> digestBytes(List<int> data) {
    ArgumentError.checkNotNull(data, 'data');

    return digestStream(Stream.value(data));
  }

  @override
  Future<Uint8List> digestStream(Stream<List<int>> data) async {
    ArgumentError.checkNotNull(data, 'data');

    return await _withEVP_MD_CTX((ctx) async {
      _checkOp(ssl.EVP_DigestInit(ctx, MD) == 1);
      await _streamToUpdate(data, ctx, ssl.EVP_DigestUpdate);
      final size = ssl.EVP_MD_CTX_size(ctx);
      _checkOp(size > 0);
      return _withOutPointer(size, (ffi.Pointer<ssl.Bytes> p) {
        _checkOp(ssl.EVP_DigestFinal(ctx, p, ffi.nullptr) == 1);
      });
    });
  }
}

class _Sha1 extends _Hash {
  const _Sha1();

  @override
  ffi.Pointer<ssl.EVP_MD> Function() get _algorithm => ssl.EVP_sha1;
}

class _Sha256 extends _Hash {
  const _Sha256();

  @override
  ffi.Pointer<ssl.EVP_MD> Function() get _algorithm => ssl.EVP_sha256;
}

class _Sha384 extends _Hash {
  const _Sha384();

  @override
  ffi.Pointer<ssl.EVP_MD> Function() get _algorithm => ssl.EVP_sha384;
}

class _Sha512 extends _Hash {
  const _Sha512();

  @override
  ffi.Pointer<ssl.EVP_MD> Function() get _algorithm => ssl.EVP_sha512;
}

const Hash sha1 = _Sha1();
const Hash sha256 = _Sha256();
const Hash sha384 = _Sha384();
const Hash sha512 = _Sha512();

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

Future<HmacSecretKey> hmacSecretKey_importRawKey(
  List<int> keyData,
  Hash hash, {
  int length,
}) async {
  return _HmacSecretKey(
    _asUint8ListZeroedToBitLength(keyData, length),
    _Hash.fromHash(hash).MD,
  );
}

Future<HmacSecretKey> hmacSecretKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  Hash hash, {
  int length,
}) =>
    throw _notImplemented;

Future<HmacSecretKey> hmacSecretKey_generateKey(Hash hash, {int length}) async {
  length ??= ssl.EVP_MD_size(_Hash.fromHash(hash).MD) * 8;
  final keyData = Uint8List((length / 8).ceil());
  fillRandomBytes(keyData);

  return _HmacSecretKey(
    _asUint8ListZeroedToBitLength(keyData, length),
    _Hash.fromHash(hash).MD,
  );
}

class _HmacSecretKey implements HmacSecretKey {
  final ffi.Pointer<ssl.EVP_MD> _hash;
  final Uint8List _keyData;

  _HmacSecretKey(this._keyData, this._hash);

  @override
  Future<Uint8List> signBytes(List<int> data) {
    ArgumentError.checkNotNull(data, 'data');

    return signStream(Stream.value(data));
  }

  @override
  Future<Uint8List> signStream(Stream<List<int>> data) async {
    final ctx = ssl.HMAC_CTX_new();
    _checkOp(ctx.address != 0, fallback: 'allocation error');
    try {
      _withDataAsPointer(_keyData, (ffi.Pointer<ssl.Data> p) {
        final n = _keyData.length;
        _checkOp(ssl.HMAC_Init_ex(ctx, p, n, _hash, ffi.nullptr) == 1);
      });
      await _streamToUpdate(data, ctx, ssl.HMAC_Update);

      final size = ssl.HMAC_size(ctx);
      _checkOp(size > 0);
      return _withAllocation(1, (ffi.Pointer<ffi.Uint32> psize) async {
        psize.value = size;
        return _withOutPointer(size, (ffi.Pointer<ssl.Bytes> p) {
          _checkOp(ssl.HMAC_Final(ctx, p, psize) == 1);
        }).sublist(0, psize.value);
      });
    } finally {
      ssl.HMAC_CTX_free(ctx);
    }
  }

  @override
  Future<bool> verifyBytes(List<int> signature, List<int> data) {
    ArgumentError.checkNotNull(signature, 'signature');
    ArgumentError.checkNotNull(data, 'data');

    return verifyStream(signature, Stream.value(data));
  }

  @override
  Future<bool> verifyStream(List<int> signature, Stream<List<int>> data) async {
    ArgumentError.checkNotNull(signature, 'signature');
    ArgumentError.checkNotNull(data, 'data');

    final other = await signStream(data);
    if (signature.length != other.length) {
      return false;
    }
    return _withDataAsPointer(signature, (ffi.Pointer<ssl.Data> s) {
      return _withDataAsPointer(other, (ffi.Pointer<ssl.Data> o) {
        return ssl.CRYPTO_memcmp(s, o, other.length) == 0;
      });
    });
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() {
    throw _notImplemented;
  }

  @override
  Future<Uint8List> exportRawKey() async {
    return Uint8List.fromList(_keyData);
  }
}

//---------------------- RSASSA_PKCS1_v1_5

Future<RsassaPkcs1V15PrivateKey> rsassaPkcs1V15PrivateKey_importPkcs8Key(
  List<int> keyData,
  Hash hash,
) async {
  // Get md first, to avoid a leak of EVP_PKEY if _Hash.fromHash throws
  final md = _Hash.fromHash(hash).MD;
  return _RsassaPkcs1V15PrivateKey(_importPkcs8RsaPrivateKey(keyData), md);
}

Future<RsassaPkcs1V15PrivateKey> rsassaPkcs1V15PrivateKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  Hash hash,
) =>
    throw _notImplemented;

Future<KeyPair<RsassaPkcs1V15PrivateKey, RsassaPkcs1V15PublicKey>>
    rsassaPkcs1V15PrivateKey_generateKey(
  int modulusLength,
  BigInt publicExponent,
  Hash hash,
) async {
  // Get md first, to avoid a leak of EVP_PKEY if _Hash.fromHash throws
  final md = _Hash.fromHash(hash).MD;
  final keys = _generateRsaKeyPair(modulusLength, publicExponent);
  return _KeyPair(
    privateKey: _RsassaPkcs1V15PrivateKey(keys.privateKey, md),
    publicKey: _RsassaPkcs1V15PublicKey(keys.publicKey, md),
  );
}

Future<RsassaPkcs1V15PublicKey> rsassaPkcs1V15PublicKey_importSpkiKey(
  List<int> keyData,
  Hash hash,
) async {
  // Get md first, to avoid a leak of EVP_PKEY if _Hash.fromHash throws
  final md = _Hash.fromHash(hash).MD;
  return _RsassaPkcs1V15PublicKey(_importSpkiRsaPublicKey(keyData), md);
}

Future<RsassaPkcs1V15PublicKey> rsassaPkcs1V15PublicKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  Hash hash,
) =>
    throw _notImplemented;

class _RsassaPkcs1V15PrivateKey
    with _Disposable
    implements RsassaPkcs1V15PrivateKey {
  final ffi.Pointer<ssl.EVP_PKEY> _key;
  final ffi.Pointer<ssl.EVP_MD> _hash;

  _RsassaPkcs1V15PrivateKey(this._key, this._hash);

  @override
  void _finalize() {
    ssl.EVP_PKEY_free(_key);
  }

  @override
  Future<Uint8List> signBytes(List<int> data) {
    ArgumentError.checkNotNull(data, 'data');
    return signStream(Stream.value(data));
  }

  @override
  Future<Uint8List> signStream(Stream<List<int>> data) {
    ArgumentError.checkNotNull(data, 'data');

    return _withEVP_MD_CTX((ctx) async {
      return await _withPEVP_PKEY_CTX((pctx) async {
        _checkOpIsOne(
          ssl.EVP_DigestSignInit(ctx, pctx, _hash, ffi.nullptr, _key),
        );
        _checkOpIsOne(
          ssl.EVP_PKEY_CTX_set_rsa_padding(pctx.value, ssl.RSA_PKCS1_PADDING),
        );
        await _streamToUpdate(data, ctx, ssl.EVP_DigestSignUpdate);
        return _withAllocation(1, (ffi.Pointer<ffi.IntPtr> len) {
          len.value = 0;
          _checkOpIsOne(ssl.EVP_DigestSignFinal(ctx, ffi.nullptr, len));
          return _withOutPointer(len.value, (ffi.Pointer<ssl.Bytes> p) {
            _checkOpIsOne(ssl.EVP_DigestSignFinal(ctx, p, len));
          }).sublist(0, len.value);
        });
      });
    });
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() {
    throw _notImplemented;
  }

  @override
  Future<Uint8List> exportPkcs8Key() async {
    return _withOutCBB((cbb) {
      _checkOp(ssl.EVP_marshal_private_key(cbb, _key) == 1);
    });
  }
}

class _RsassaPkcs1V15PublicKey
    with _Disposable
    implements RsassaPkcs1V15PublicKey {
  final ffi.Pointer<ssl.EVP_PKEY> _key;
  final ffi.Pointer<ssl.EVP_MD> _hash;

  _RsassaPkcs1V15PublicKey(this._key, this._hash);

  @override
  void _finalize() {
    ssl.EVP_PKEY_free(_key);
  }

  @override
  Future<bool> verifyBytes(List<int> signature, List<int> data) {
    ArgumentError.checkNotNull(signature, 'signature');
    ArgumentError.checkNotNull(data, 'data');
    return verifyStream(signature, Stream.value(data));
  }

  @override
  Future<bool> verifyStream(List<int> signature, Stream<List<int>> data) {
    ArgumentError.checkNotNull(signature, 'signature');
    ArgumentError.checkNotNull(data, 'data');

    return _withEVP_MD_CTX((ctx) async {
      return _withPEVP_PKEY_CTX((pctx) async {
        _checkOpIsOne(
          ssl.EVP_DigestVerifyInit(ctx, pctx, _hash, ffi.nullptr, _key),
        );
        _checkOpIsOne(
          ssl.EVP_PKEY_CTX_set_rsa_padding(pctx.value, ssl.RSA_PKCS1_PADDING),
        );
        await _streamToUpdate(data, ctx, ssl.EVP_DigestVerifyUpdate);
        return _withDataAsPointer(signature, (ffi.Pointer<ssl.Bytes> p) {
          final result = ssl.EVP_DigestVerifyFinal(ctx, p, signature.length);
          return result == 1;
        });
      });
    });
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() {
    throw _notImplemented;
  }

  @override
  Future<Uint8List> exportSpkiKey() async {
    return _withOutCBB((cbb) {
      _checkOp(ssl.EVP_marshal_public_key(cbb, _key) == 1);
    });
  }
}

//---------------------- RSA-PSS

Future<RsaPssPrivateKey> rsaPssPrivateKey_importPkcs8Key(
  List<int> keyData,
  Hash hash,
) async {
  // Get md first, to avoid a leak of EVP_PKEY if _Hash.fromHash throws
  final md = _Hash.fromHash(hash).MD;
  return _RsaPssPrivateKey(_importPkcs8RsaPrivateKey(keyData), md);
}

Future<RsaPssPrivateKey> rsaPssPrivateKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  Hash hash,
) =>
    throw _notImplemented;

Future<KeyPair<RsaPssPrivateKey, RsaPssPublicKey>> rsaPssPrivateKey_generateKey(
  int modulusLength,
  BigInt publicExponent,
  Hash hash,
) async {
  // Get md first, to avoid a leak of EVP_PKEY if _Hash.fromHash throws
  final md = _Hash.fromHash(hash).MD;
  final keys = _generateRsaKeyPair(modulusLength, publicExponent);
  return _KeyPair(
    privateKey: _RsaPssPrivateKey(keys.privateKey, md),
    publicKey: _RsaPssPublicKey(keys.publicKey, md),
  );
}

Future<RsaPssPublicKey> rsaPssPublicKey_importSpkiKey(
  List<int> keyData,
  Hash hash,
) async {
  // Get md first, to avoid a leak of EVP_PKEY if _Hash.fromHash throws
  final md = _Hash.fromHash(hash).MD;
  return _RsaPssPublicKey(_importSpkiRsaPublicKey(keyData), md);
}

Future<RsaPssPublicKey> rsaPssPublicKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  Hash hash,
) =>
    throw _notImplemented;

class _RsaPssPrivateKey with _Disposable implements RsaPssPrivateKey {
  final ffi.Pointer<ssl.EVP_PKEY> _key;
  final ffi.Pointer<ssl.EVP_MD> _hash;

  _RsaPssPrivateKey(this._key, this._hash);

  @override
  void _finalize() {
    ssl.EVP_PKEY_free(_key);
  }

  @override
  Future<Uint8List> signBytes(List<int> data, int saltLength) {
    ArgumentError.checkNotNull(data, 'data');
    ArgumentError.checkNotNull(saltLength, 'saltLength');
    return signStream(Stream.value(data), saltLength);
  }

  @override
  Future<Uint8List> signStream(Stream<List<int>> data, int saltLength) {
    ArgumentError.checkNotNull(data, 'data');
    ArgumentError.checkNotNull(saltLength, 'saltLength');
    if (saltLength <= 0) {
      throw ArgumentError.value(
        saltLength,
        'saltLength',
        'must be a positive integer',
      );
    }

    return _withEVP_MD_CTX((ctx) async {
      return await _withPEVP_PKEY_CTX((pctx) async {
        _checkOpIsOne(
          ssl.EVP_DigestSignInit(ctx, pctx, _hash, ffi.nullptr, _key),
        );
        _checkOpIsOne(ssl.EVP_PKEY_CTX_set_rsa_padding(
          pctx.value,
          ssl.RSA_PKCS1_PSS_PADDING,
        ));
        _checkDataIsOne(ssl.EVP_PKEY_CTX_set_rsa_pss_saltlen(
          pctx.value,
          saltLength,
        ));
        _checkDataIsOne(ssl.EVP_PKEY_CTX_set_rsa_mgf1_md(pctx.value, _hash));
        await _streamToUpdate(data, ctx, ssl.EVP_DigestSignUpdate);
        return _withAllocation(1, (ffi.Pointer<ffi.IntPtr> len) {
          len.value = 0;
          _checkOpIsOne(ssl.EVP_DigestSignFinal(ctx, ffi.nullptr, len));
          return _withOutPointer(len.value, (ffi.Pointer<ssl.Bytes> p) {
            _checkOpIsOne(ssl.EVP_DigestSignFinal(ctx, p, len));
          }).sublist(0, len.value);
        });
      });
    });
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() {
    throw _notImplemented;
  }

  @override
  Future<Uint8List> exportPkcs8Key() async {
    return _withOutCBB((cbb) {
      _checkOp(ssl.EVP_marshal_private_key(cbb, _key) == 1);
    });
  }
}

class _RsaPssPublicKey with _Disposable implements RsaPssPublicKey {
  final ffi.Pointer<ssl.EVP_PKEY> _key;
  final ffi.Pointer<ssl.EVP_MD> _hash;

  _RsaPssPublicKey(this._key, this._hash);

  @override
  void _finalize() {
    ssl.EVP_PKEY_free(_key);
  }

  @override
  Future<bool> verifyBytes(
    List<int> signature,
    List<int> data,
    int saltLength,
  ) {
    ArgumentError.checkNotNull(signature, 'signature');
    ArgumentError.checkNotNull(data, 'data');
    ArgumentError.checkNotNull(saltLength, 'saltLength');
    return verifyStream(signature, Stream.value(data), saltLength);
  }

  @override
  Future<bool> verifyStream(
    List<int> signature,
    Stream<List<int>> data,
    int saltLength,
  ) {
    ArgumentError.checkNotNull(signature, 'signature');
    ArgumentError.checkNotNull(data, 'data');
    ArgumentError.checkNotNull(saltLength, 'saltLength');

    if (saltLength <= 0) {
      throw ArgumentError.value(
        saltLength,
        'saltLength',
        'must be a positive integer',
      );
    }

    return _withEVP_MD_CTX((ctx) async {
      return _withPEVP_PKEY_CTX((pctx) async {
        _checkOpIsOne(
          ssl.EVP_DigestVerifyInit(ctx, pctx, _hash, ffi.nullptr, _key),
        );
        _checkOpIsOne(ssl.EVP_PKEY_CTX_set_rsa_padding(
          pctx.value,
          ssl.RSA_PKCS1_PSS_PADDING,
        ));
        _checkDataIsOne(ssl.EVP_PKEY_CTX_set_rsa_pss_saltlen(
          pctx.value,
          saltLength,
        ));
        _checkDataIsOne(ssl.EVP_PKEY_CTX_set_rsa_mgf1_md(pctx.value, _hash));
        await _streamToUpdate(data, ctx, ssl.EVP_DigestVerifyUpdate);
        return _withDataAsPointer(signature, (ffi.Pointer<ssl.Bytes> p) {
          final result = ssl.EVP_DigestVerifyFinal(ctx, p, signature.length);
          return result == 1;
        });
      });
    });
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() {
    throw _notImplemented;
  }

  @override
  Future<Uint8List> exportSpkiKey() async {
    return _withOutCBB((cbb) {
      _checkOp(ssl.EVP_marshal_public_key(cbb, _key) == 1);
    });
  }
}

//---------------------- ECDSA

/// Get `ssl.NID_...` from BoringSSL matching the given [curve].
int _curveToNID(EllipticCurve curve) {
  ArgumentError.checkNotNull(curve, 'curve');

  if (curve == EllipticCurve.p256) {
    return ssl.NID_X9_62_prime256v1;
  }
  if (curve == EllipticCurve.p384) {
    return ssl.NID_secp384r1;
  }
  if (curve == EllipticCurve.p521) {
    return ssl.NID_secp521r1;
  }
  // This should never happen!
  throw UnsupportedError('curve "$curve" is not supported');
}

/// Perform some post-import validation for EC keys.
void _validateEllipticCurveKey(
  ffi.Pointer<ssl.EVP_PKEY> key,
  EllipticCurve curve,
) {
  _checkData(ssl.EVP_PKEY_id(key) == ssl.EVP_PKEY_EC,
      message: 'key is not an EC key');

  final ec = ssl.EVP_PKEY_get0_EC_KEY(key);
  _checkData(ec.address != 0, fallback: 'key is not an EC key');
  _checkDataIsOne(ssl.EC_KEY_check_key(ec), fallback: 'invalid key');

  // When importing BoringSSL will compute the public key if omitted, and
  // leave a flag, such that exporting the private key won't include the
  // public key.
  final encFlags = ssl.EC_KEY_get_enc_flags(ec);
  ssl.EC_KEY_set_enc_flags(ec, encFlags & ~ssl.EC_PKEY_NO_PUBKEY);

  // Check the curve of the imported key
  final nid = ssl.EC_GROUP_get_curve_name(ssl.EC_KEY_get0_group(ec));
  _checkData(_curveToNID(curve) != nid, message: 'incorrect elliptic curve');
}

Future<EcdsaPrivateKey> ecdsaPrivateKey_importPkcs8Key(
  List<int> keyData,
  EllipticCurve curve,
) async {
  final key = _withDataAsCBS(keyData, ssl.EVP_parse_private_key);
  _checkData(key.address != 0, fallback: 'unable to parse key');

  try {
    _validateEllipticCurveKey(key, curve);
    return _EcdsaPrivateKey(key);
  } catch (_) {
    // We only free key if an exception/error was thrown
    ssl.EVP_PKEY_free(key);
    rethrow;
  }
}

Future<EcdsaPrivateKey> ecdsaPrivateKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  EllipticCurve curve,
) =>
    throw _notImplemented;

Future<KeyPair<EcdsaPrivateKey, EcdsaPublicKey>> ecdsaPrivateKey_generateKey(
  EllipticCurve curve,
) async {
  final ecPriv = ssl.EC_KEY_new_by_curve_name(_curveToNID(curve));
  _checkOp(ecPriv.address != 0, fallback: 'internal failure to use curve');

  try {
    _checkOpIsOne(ssl.EC_KEY_generate_key(ecPriv),
        fallback: 'key generation failed');

    final privKey = ssl.EVP_PKEY_new();
    _checkOp(privKey.address != 0);
    try {
      final ecPub = ssl.EC_KEY_new_by_curve_name(_curveToNID(curve));
      _checkOp(ecPub.address != 0);
      try {
        _checkOpIsOne(ssl.EC_KEY_set_public_key(
          ecPub,
          ssl.EC_KEY_get0_public_key(ecPriv),
        ));

        final pubKey = ssl.EVP_PKEY_new();
        _checkOp(pubKey.address != 0);
        try {
          _checkOpIsOne(ssl.EVP_PKEY_set1_EC_KEY(pubKey, ecPub));

          return _KeyPair(
            privateKey: _EcdsaPrivateKey(privKey),
            publicKey: _EcdsaPublicKey(pubKey),
          );
        } catch (_) {
          ssl.EVP_PKEY_free(pubKey);
          rethrow;
        }
      } finally {
        ssl.EC_KEY_free(ecPub);
      }
    } catch (_) {
      ssl.EVP_PKEY_free(privKey);
      rethrow;
    }
  } finally {
    ssl.EC_KEY_free(ecPriv);
  }
}

Future<EcdsaPublicKey> ecdsaPublicKey_importRawKey(
  List<int> keyData,
  EllipticCurve curve,
) async {
  // See: https://chromium.googlesource.com/chromium/src/+/43d62c50b705f88c67b14539e91fd8fd017f70c4/components/webcrypto/algorithms/ec.cc#332

  // Create EC_KEY for the curve
  final ec = ssl.EC_KEY_new_by_curve_name(_curveToNID(curve));
  _checkOp(ec.address != 0, fallback: 'internal failure to use curve');

  try {
    // Create EC_POINT to hold public key info
    final pub = ssl.EC_POINT_new(ssl.EC_KEY_get0_group(ec));
    _checkOp(pub.address != 0, fallback: 'internal point allocation error');
    try {
      // Read raw public key
      _withDataAsPointer(keyData, (ffi.Pointer<ssl.Bytes> p) {
        _checkDataIsOne(
          ssl.EC_POINT_oct2point(
              ssl.EC_KEY_get0_group(ec), pub, p, keyData.length, ffi.nullptr),
          fallback: 'invalid keyData',
        );
      });
      // Copy pub point to ec
      _checkDataIsOne(ssl.EC_KEY_set_public_key(ec, pub),
          fallback: 'invalid keyData');
      final key = ssl.EVP_PKEY_new();
      try {
        _checkOpIsOne(ssl.EVP_PKEY_set1_EC_KEY(key, ec));
        _validateEllipticCurveKey(key, curve);
        return _EcdsaPublicKey(key);
      } catch (_) {
        ssl.EVP_PKEY_free(key);
        rethrow;
      }
    } finally {
      ssl.EC_POINT_free(pub);
    }
  } finally {
    ssl.EC_KEY_free(ec);
  }
}

Future<EcdsaPublicKey> ecdsaPublicKey_importSpkiKey(
  List<int> keyData,
  EllipticCurve curve,
) async {
  // TODO: When calling EVP_parse_public_key it might wise to check that CBS_len(cbs) == 0 is true afterwards
  // otherwise it might be that all of the contents of the key was not consumed and we should throw
  // a FormatException. Notice that this the case for private/public keys, and RSA keys.
  final key = _withDataAsCBS(keyData, ssl.EVP_parse_public_key);
  _checkData(key.address != 0, fallback: 'unable to parse key');

  try {
    _validateEllipticCurveKey(key, curve);

    return _EcdsaPublicKey(key);
  } catch (_) {
    // We only free key if an exception/error was thrown
    ssl.EVP_PKEY_free(key);
    rethrow;
  }
}

Future<EcdsaPublicKey> ecdsaPublicKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  EllipticCurve curve,
) =>
    throw _notImplemented;

/// Convert ECDSA signature in DER format returned by BoringSSL to the raw R + S
/// formated specified in the webcrypto specification.
///
/// See also: https://chromium.googlesource.com/chromium/src/+/43d62c50b705f88c67b14539e91fd8fd017f70c4/components/webcrypto/algorithms/ecdsa.cc#69
Uint8List _convertEcdsaDerSignatureToWebCryptoSignature(
  ffi.Pointer<ssl.EVP_PKEY> key,
  Uint8List signature,
) {
  final ecdsa = _withDataAsCBS(signature, ssl.ECDSA_SIG_parse);
  _checkOp(ecdsa.address != 0, message: 'internal error formatting signature');
  try {
    // Read EC key and get the number of bytes required to encode R and S.
    final ec = ssl.EVP_PKEY_get0_EC_KEY(key);
    _checkOp(ec.address != 0, message: 'internal key type invariant violation');
    final N = ssl.BN_num_bytes(ssl.EC_GROUP_get0_order(ssl.EC_KEY_get0_group(
      ec,
    )));

    return _withAllocation(2, (ffi.Pointer<ffi.Pointer<ssl.BIGNUM>> RS) {
      // Access R and S from the ecdsa signature
      final R = RS.elementAt(0);
      final S = RS.elementAt(1);
      ssl.ECDSA_SIG_get0(ecdsa, R, S);

      // Dump R and S to return value.
      return _withOutPointer(N * 2, (ffi.Pointer<ffi.Uint8> p) {
        _checkOpIsOne(
          ssl.BN_bn2bin_padded(p.elementAt(0).cast<ssl.Bytes>(), N, R.value),
          fallback: 'internal error formatting R in signature',
        );
        _checkOpIsOne(
          ssl.BN_bn2bin_padded(p.elementAt(N).cast<ssl.Bytes>(), N, S.value),
          fallback: 'internal error formatting S in signature',
        );
      });
    });
  } finally {
    ssl.ECDSA_SIG_free(ecdsa);
  }
}

/// Convert ECDSA signature in the raw R + S as specified in webcrypto to DER
/// format as expected by BoringSSL.
///
/// Returns `null` if the [signature] is invalid and should be rejected.
///
/// See also: https://chromium.googlesource.com/chromium/src/+/43d62c50b705f88c67b14539e91fd8fd017f70c4/components/webcrypto/algorithms/ecdsa.cc#111
Uint8List _convertEcdsaWebCryptoSignatureToDerSignature(
  ffi.Pointer<ssl.EVP_PKEY> key,
  Uint8List signature,
) {
  // Read EC key and get the number of bytes required to encode R and S.
  final ec = ssl.EVP_PKEY_get0_EC_KEY(key);
  _checkOp(ec.address != 0, message: 'internal key type invariant violation');
  final N = ssl.BN_num_bytes(ssl.EC_GROUP_get0_order(ssl.EC_KEY_get0_group(
    ec,
  )));

  if (N * 2 == signature.length) {
    // If the signature format is invalid we consider the signature invalid and
    // return false from verification method. This follows:
    // https://chromium.googlesource.com/chromium/src/+/43d62c50b705f88c67b14539e91fd8fd017f70c4/components/webcrypto/algorithms/ecdsa.cc#111
    return null;
  }

  final ecdsa = ssl.ECDSA_SIG_new();
  _checkOp(ecdsa.address != 0, message: 'internal error formatting signature');
  try {
    return _withAllocation(2, (ffi.Pointer<ffi.Pointer<ssl.BIGNUM>> RS) {
      // Access R and S from the ecdsa signature
      final R = RS.elementAt(0);
      final S = RS.elementAt(1);
      ssl.ECDSA_SIG_get0(ecdsa, R, S);

      _withDataAsPointer(signature, (ffi.Pointer<ffi.Uint8> p) {
        _checkOp(
          ssl.BN_bin2bn(p.elementAt(0).cast<ssl.Bytes>(), N, R.value).address !=
              0,
          fallback: 'allocation failure',
        );
        _checkOp(
          ssl.BN_bin2bn(p.elementAt(N).cast<ssl.Bytes>(), N, S.value).address !=
              0,
          fallback: 'allocation failure',
        );
      });
      return _withOutCBB((cbb) => _checkOpIsOne(
            ssl.ECDSA_SIG_marshal(cbb, ecdsa),
            fallback: 'internal error reformatting signature',
          ));
    });
  } finally {
    ssl.ECDSA_SIG_free(ecdsa);
  }
}

class _EcdsaPrivateKey with _Disposable implements EcdsaPrivateKey {
  final ffi.Pointer<ssl.EVP_PKEY> _key;

  _EcdsaPrivateKey(this._key);

  @override
  void _finalize() {
    ssl.EVP_PKEY_free(_key);
  }

  @override
  Future<Uint8List> signBytes(List<int> data, Hash hash) {
    ArgumentError.checkNotNull(data, 'data');
    ArgumentError.checkNotNull(hash, 'hash');
    return signStream(Stream.value(data), hash);
  }

  @override
  Future<Uint8List> signStream(Stream<List<int>> data, Hash hash) async {
    ArgumentError.checkNotNull(data, 'data');
    ArgumentError.checkNotNull(hash, 'hash');
    final _hash = _Hash.fromHash(hash).MD;

    final sig = await _withEVP_MD_CTX((ctx) async {
      _checkOpIsOne(
        ssl.EVP_DigestSignInit(ctx, ffi.nullptr, _hash, ffi.nullptr, _key),
      );

      await _streamToUpdate(data, ctx, ssl.EVP_DigestSignUpdate);
      return _withAllocation(1, (ffi.Pointer<ffi.IntPtr> len) {
        len.value = 0;
        _checkOpIsOne(ssl.EVP_DigestSignFinal(ctx, ffi.nullptr, len));
        return _withOutPointer(len.value, (ffi.Pointer<ssl.Bytes> p) {
          _checkOpIsOne(ssl.EVP_DigestSignFinal(ctx, p, len));
        }).sublist(0, len.value);
      });
    });
    return _convertEcdsaDerSignatureToWebCryptoSignature(_key, sig);
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() {
    throw _notImplemented;
  }

  @override
  Future<Uint8List> exportPkcs8Key() async {
    return _withOutCBB((cbb) {
      _checkOp(ssl.EVP_marshal_private_key(cbb, _key) == 1);
    });
  }
}

class _EcdsaPublicKey with _Disposable implements EcdsaPublicKey {
  final ffi.Pointer<ssl.EVP_PKEY> _key;

  _EcdsaPublicKey(this._key);

  @override
  void _finalize() {
    ssl.EVP_PKEY_free(_key);
  }

  @override
  Future<bool> verifyBytes(List<int> signature, List<int> data, Hash hash) {
    ArgumentError.checkNotNull(signature, 'signature');
    ArgumentError.checkNotNull(data, 'data');
    ArgumentError.checkNotNull(hash, 'hash');
    return verifyStream(signature, Stream.value(data), hash);
  }

  @override
  Future<bool> verifyStream(
    List<int> signature,
    Stream<List<int>> data,
    Hash hash,
  ) async {
    ArgumentError.checkNotNull(signature, 'signature');
    ArgumentError.checkNotNull(data, 'data');
    ArgumentError.checkNotNull(hash, 'hash');
    final _hash = _Hash.fromHash(hash).MD;

    // Convert to DER signature
    final sig = _convertEcdsaWebCryptoSignatureToDerSignature(_key, signature);
    if (sig == null) {
      // If signature format is invalid we fail verification
      return false;
    }

    return await _withEVP_MD_CTX((ctx) async {
      return await _withPEVP_PKEY_CTX((pctx) async {
        _checkOpIsOne(
          ssl.EVP_DigestVerifyInit(ctx, pctx, _hash, ffi.nullptr, _key),
        );
        await _streamToUpdate(data, ctx, ssl.EVP_DigestVerifyUpdate);
        return _withDataAsPointer(sig, (ffi.Pointer<ssl.Bytes> p) {
          final result = ssl.EVP_DigestVerifyFinal(ctx, p, sig.length);
          return result == 1;
        });
      });
    });
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() {
    throw _notImplemented;
  }

  @override
  Future<Uint8List> exportRawKey() async {
    final ec = ssl.EVP_PKEY_get0_EC_KEY(_key);
    _checkOp(ec.address != null, fallback: 'internal key type invariant error');

    return _withOutCBB((cbb) {
      return _checkOpIsOne(
          ssl.EC_POINT_point2cbb(
            cbb,
            ssl.EC_KEY_get0_group(ec),
            ssl.EC_KEY_get0_public_key(ec),
            ssl.POINT_CONVERSION_UNCOMPRESSED,
            ffi.nullptr,
          ),
          fallback: 'formatting failed');
    });
  }

  @override
  Future<Uint8List> exportSpkiKey() async {
    return _withOutCBB((cbb) {
      _checkOp(ssl.EVP_marshal_public_key(cbb, _key) == 1);
    });
  }
}

//---------------------- RSA-OAEP

Future<RsaOaepPrivateKey> rsaOaepPrivateKey_importPkcs8Key(
  List<int> keyData,
  Hash hash,
) async {
  // Get md first, to avoid a leak of EVP_PKEY if _Hash.fromHash throws
  final md = _Hash.fromHash(hash).MD;
  return _RsaOaepPrivateKey(_importPkcs8RsaPrivateKey(keyData), md);
}

Future<RsaOaepPrivateKey> rsaOaepPrivateKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  Hash hash,
) =>
    throw _notImplemented;

Future<KeyPair<RsaOaepPrivateKey, RsaPssPublicKey>>
    rsaOaepPrivateKey_generateKey(
  int modulusLength,
  BigInt publicExponent,
  Hash hash,
) async {
  // Get md first, to avoid a leak of EVP_PKEY if _Hash.fromHash throws
  final md = _Hash.fromHash(hash).MD;
  final keys = _generateRsaKeyPair(modulusLength, publicExponent);
  return _KeyPair(
    privateKey: _RsaOaepPrivateKey(keys.privateKey, md),
    publicKey: _RsaPssPublicKey(keys.publicKey, md),
  );
}

Future<RsaOaepPublicKey> rsaOaepPublicKey_importSpkiKey(
  List<int> keyData,
  Hash hash,
) async {
  // Get md first, to avoid a leak of EVP_PKEY if _Hash.fromHash throws
  final md = _Hash.fromHash(hash).MD;
  return _RsaOaepPublicKey(_importSpkiRsaPublicKey(keyData), md);
}

Future<RsaOaepPublicKey> rsaOaepPublicKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  Hash hash,
) =>
    throw _notImplemented;

/// Utility method to encrypt or decrypt with RSA-OAEP.
///
/// Expects:
///  * [initFn] as [ssl.EVP_PKEY_encrypt_init] or [ssl.EVP_PKEY_decrypt_init] ,
///  * [encryptOrDecryptFn] as [ssl.EVP_PKEY_encrypt] or [ssl.EVP_PKEY_decrypt].
Future<Uint8List> _rsaOaepeEncryptOrDecryptBytes(
  ffi.Pointer<ssl.EVP_PKEY> key,
  ffi.Pointer<ssl.EVP_MD> md,
  // ssl.EVP_PKEY_encrypt_init
  int Function(ffi.Pointer<ssl.EVP_PKEY_CTX>) initFn,
  // ssl.EVP_PKEY_encrypt
  int Function(
    ffi.Pointer<ssl.EVP_PKEY_CTX>,
    ffi.Pointer<ssl.Bytes>,
    ffi.Pointer<ffi.IntPtr>,
    ffi.Pointer<ssl.Bytes>,
    int,
  )
      encryptOrDecryptFn,
  List<int> data, {
  List<int> label,
}) async {
  ArgumentError.checkNotNull(data, 'data');

  final ctx = ssl.EVP_PKEY_CTX_new(key, ffi.nullptr);
  _checkOp(ctx.address != 0, fallback: 'allocation error');
  try {
    _checkOpIsOne(initFn(ctx));
    _checkOpIsOne(
      ssl.EVP_PKEY_CTX_set_rsa_padding(ctx, ssl.RSA_PKCS1_OAEP_PADDING),
    );
    _checkOpIsOne(ssl.EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md));
    _checkOpIsOne(ssl.EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md));

    // Copy and set label
    if (label != null && label.isNotEmpty) {
      final plabel = ssl.OPENSSL_malloc(label.length);
      _checkOp(plabel.address != 0);
      try {
        plabel.cast<ffi.Uint8>().asTypedList(label.length).setAll(0, label);
        _checkOpIsOne(ssl.EVP_PKEY_CTX_set0_rsa_oaep_label(
          ctx,
          plabel.cast<ssl.Bytes>(),
          label.length,
        ));
      } catch (_) {
        // Ownership is transferred to ctx by EVP_PKEY_CTX_set0_rsa_oaep_label
        ssl.OPENSSL_free(plabel);
        rethrow;
      }
    }

    return _withDataAsPointer(data, (ffi.Pointer<ssl.Bytes> input) {
      return _withAllocation(1, (ffi.Pointer<ffi.IntPtr> len) {
        len.value = 0;
        _checkOpIsOne(encryptOrDecryptFn(
          ctx,
          ffi.nullptr,
          len,
          input,
          data.length,
        ));
        return _withOutPointer(len.value, (ffi.Pointer<ssl.Bytes> output) {
          _checkOpIsOne(encryptOrDecryptFn(
            ctx,
            output,
            len,
            input,
            data.length,
          ));
        }).sublist(0, len.value);
      });
    });
  } finally {
    ssl.EVP_PKEY_CTX_free(ctx);
  }
}

class _RsaOaepPrivateKey with _Disposable implements RsaOaepPrivateKey {
  final ffi.Pointer<ssl.EVP_PKEY> _key;
  final ffi.Pointer<ssl.EVP_MD> _hash;

  _RsaOaepPrivateKey(this._key, this._hash);

  @override
  void _finalize() {
    ssl.EVP_PKEY_free(_key);
  }

  @override
  Future<Uint8List> decryptBytes(List<int> data, {List<int> label}) async {
    ArgumentError.checkNotNull(data, 'data');
    return _rsaOaepeEncryptOrDecryptBytes(
      _key,
      _hash,
      ssl.EVP_PKEY_decrypt_init,
      ssl.EVP_PKEY_decrypt,
      data,
      label: label,
    );
  }

  @override
  Stream<Uint8List> decryptStream(Stream<List<int>> data, {List<int> label}) {
    throw UnsupportedError('TODO: Remove this method from the interface');
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() {
    throw _notImplemented;
  }

  @override
  Future<Uint8List> exportPkcs8Key() async {
    return _withOutCBB((cbb) {
      _checkOp(ssl.EVP_marshal_private_key(cbb, _key) == 1);
    });
  }
}

class _RsaOaepPublicKey with _Disposable implements RsaOaepPublicKey {
  final ffi.Pointer<ssl.EVP_PKEY> _key;
  final ffi.Pointer<ssl.EVP_MD> _hash;

  _RsaOaepPublicKey(this._key, this._hash);

  @override
  void _finalize() {
    ssl.EVP_PKEY_free(_key);
  }

  @override
  Future<Uint8List> encryptBytes(List<int> data, {List<int> label}) async {
    ArgumentError.checkNotNull(data, 'data');
    return _rsaOaepeEncryptOrDecryptBytes(
      _key,
      _hash,
      ssl.EVP_PKEY_encrypt_init,
      ssl.EVP_PKEY_encrypt,
      data,
      label: label,
    );
  }

  @override
  Stream<Uint8List> encryptStream(Stream<List<int>> data, {List<int> label}) {
    throw UnsupportedError('TODO: Remove this method from the interface');
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() {
    throw _notImplemented;
  }

  @override
  Future<Uint8List> exportSpkiKey() async {
    return _withOutCBB((cbb) {
      _checkOp(ssl.EVP_marshal_public_key(cbb, _key) == 1);
    });
  }
}

//---------------------- AES-CTR

Future<AesCtrSecretKey> aesCtr_importRawKey(List<int> keyData) =>
    throw _notImplemented;

Future<AesCtrSecretKey> aesCtr_importJsonWebKey(Map<String, dynamic> jwk) =>
    throw _notImplemented;

Future<AesCtrSecretKey> aesCtr_generateKey(int length) => throw _notImplemented;

//---------------------- AES-CBC

Future<AesCbcSecretKey> aesCbc_importRawKey(List<int> keyData) =>
    throw _notImplemented;

Future<AesCbcSecretKey> aesCbc_importJsonWebKey(Map<String, dynamic> jwk) =>
    throw _notImplemented;

Future<AesCbcSecretKey> aesCbc_generateKey(int length) => throw _notImplemented;

//---------------------- AES-GCM

Future<AesGcmSecretKey> aesGcm_importRawKey(List<int> keyData) =>
    throw _notImplemented;

Future<AesGcmSecretKey> aesGcm_importJsonWebKey(Map<String, dynamic> jwk) =>
    throw _notImplemented;

Future<AesGcmSecretKey> aesGcm_generateKey(int length) => throw _notImplemented;

//---------------------- ECDH

Future<EcdhPrivateKey> ecdhPrivateKey_importPkcs8Key(
  List<int> keyData,
  EllipticCurve curve,
) =>
    throw _notImplemented;

Future<EcdhPrivateKey> ecdhPrivateKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  EllipticCurve curve,
) =>
    throw _notImplemented;

Future<KeyPair<EcdhPrivateKey, EcdhPublicKey>> ecdhPrivateKey_generateKey(
  EllipticCurve curve,
) =>
    throw _notImplemented;

Future<EcdhPublicKey> ecdhPublicKey_importRawKey(
  List<int> keyData,
  EllipticCurve curve,
) =>
    throw _notImplemented;

Future<EcdhPublicKey> ecdhPublicKey_importSpkiKey(
  List<int> keyData,
  EllipticCurve curve,
) =>
    throw _notImplemented;

Future<EcdhPublicKey> ecdhPublicKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  EllipticCurve curve,
) =>
    throw _notImplemented;

//---------------------- HKDF

Future<HkdfSecretKey> hkdfSecretKey_importRawKey(List<int> keyData) =>
    throw _notImplemented;

//---------------------- PBKDF2

Future<Pbkdf2SecretKey> pbkdf2SecretKey_importRawKey(List<int> keyData) =>
    throw _notImplemented;
