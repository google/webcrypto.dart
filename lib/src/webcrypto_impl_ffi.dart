import 'dart:async';
import 'dart:typed_data';
import 'dart:convert' show utf8, base64Url;
import 'dart:ffi' as ffi;
import 'dart:math' as math;
import 'package:ffi/ffi.dart' as ffi;
import 'package:meta/meta.dart';

import 'jsonwebkey.dart' show JsonWebKey;
import '../webcrypto.dart';
import 'boringssl/boringssl.dart' as ssl;

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

/// Allocate [count] (default 1) size of [T] bytes.
///
/// Must be de-allocated with [_free].
ffi.Pointer<T> _malloc<T extends ffi.NativeType>({int count = 1}) {
  return ffi.allocate<T>(count: count);
  // TODO: Find out why this fails:
  //final p = ssl.OPENSSL_malloc(count * ffi.sizeOf<T>());
  //_checkOp(p.address != 0, fallback: 'allocation failure');
  //return p.cast<T>();
}

/// Release memory allocated with [_malloc]
void _free<T extends ffi.NativeType>(ffi.Pointer<T> p) {
  ffi.free(p);
  // TODO: Find out why this fails
  //ssl.OPENSSL_free(p.cast<ssl.Data>());
}

class _ScopeEntry {
  final Object handle;
  final void Function() fn;

  _ScopeEntry(this.handle, this.fn);
}

// Utility for tracking and releasing memory.
class _Scope {
  final List<_ScopeEntry> _deferred = [];

  /// Defer [fn] to end of this scope.
  void defer(void Function() fn, [Object handle]) =>
      _deferred.add(_ScopeEntry(handle, fn));

  /// Allocate an [ffi.Pointer<T>] in this scope.
  ffi.Pointer<T> allocate<T extends ffi.NativeType>({int count = 1}) {
    final p = _malloc<T>(count: count);
    defer(() => _free(p), p);
    return p;
  }

  /// Allocate and copy [data] to an [ffi.Pointer<T>] in this scope.
  ffi.Pointer<T> dataAsPointer<T extends ffi.NativeType>(List<int> data) {
    final p = _malloc<ffi.Uint8>(count: data.length);
    p.asTypedList(data.length).setAll(0, data);
    final result = p.cast<T>();
    defer(() => _free(p), result);
    return result;
  }

  /// Call [create], return [T], and [release] when scope is terminated.
  ffi.Pointer<T> create<T extends ffi.NativeType>(
    ffi.Pointer<T> Function() create,
    void Function(ffi.Pointer<T>) release,
  ) {
    final result = create();
    _checkOp(result.address != 0, fallback: 'allocation failed');
    defer(() => release(result), result);
    return result;
  }

  /// Move [handle] out of scope.
  ///
  /// This requires that [handle] is an object that was registered in this
  /// scope, otherwise this throws.
  T move<T>(T handle) {
    if (!_deferred.any((e) => e.handle == handle)) {
      throw StateError('Cannot move handle from Scope');
    }
    _deferred.removeWhere((e) => e.handle == handle);
    return handle;
  }

  /// Release all resources held in this scope.
  void release() {
    while (_deferred.isNotEmpty) {
      try {
        _deferred.removeLast().fn();
      } catch (e) {
        while (_deferred.isNotEmpty) {
          try {
            _deferred.removeLast().fn();
          } catch (_) {
            // Ignore error
          }
        }
        rethrow;
      }
    }
  }
}

/// Invoke [fn] with [ffi.Pointer<T>] of size count and release the pointer
/// when [fn] returns.
R _withAllocation<T extends ffi.NativeType, R>(
  int count,
  R Function(ffi.Pointer<T>) fn,
) {
  assert(R is! Future, 'avoid async blocks');
  final p = _malloc<T>(count: count);
  try {
    return fn(p);
  } finally {
    _free(p);
  }
}

/// Invoke [fn] with [ffi.Pointer<T>] of size count and release the pointer
/// when future returned by [fn] completes.
Future<R> _withAllocationAsync<T extends ffi.NativeType, R>(
  int count,
  FutureOr<R> Function(ffi.Pointer<T>) fn,
) async {
  assert(R is! Future, 'avoid nested async blocks');
  final p = _malloc<T>(count: count);
  try {
    return await fn(p);
  } finally {
    _free(p);
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
  final buffer = _malloc<ffi.Uint8>(count: maxChunk);
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
    _free(buffer);
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

  // ignore: unused_element
  static void dispose(_Disposable obj) => obj._finalize();
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

/// Get the number of bytes required to hold [numberOfBits].
///
/// This is the same as `(N / 8).ceil() * 8` without dabling in doubles.
int _numBitsToBytes(int numberOfBits) =>
    (numberOfBits ~/ 8) + ((7 + (numberOfBits % 8)) ~/ 8);

//---------------------- JWK Helpers

/// Decode url-safe base64 witout padding as specified in
/// [RFC 7515 Section 2](https://tools.ietf.org/html/rfc7515#section-2)
///
/// Throw [FormatException] mentioning JWK property [prop] on failure.
Uint8List _jwkDecodeBase64UrlNoPadding(String unpadded, String prop) {
  try {
    final padded = unpadded.padRight(
      unpadded.length + ((4 - (unpadded.length % 4)) % 4),
      '=',
    );
    return base64Url.decode(padded);
  } on FormatException {
    throw FormatException(
      'JWK property "$prop" is not url-safe base64 without padding',
      unpadded,
    );
  }
}

/// Encode url-safe base64 witout padding as specified in
/// [RFC 7515 Section 2](https://tools.ietf.org/html/rfc7515#section-2)
String _jwkEncodeBase64UrlNoPadding(List<int> data) {
  final padded = base64Url.encode(data);
  final i = padded.indexOf('=');
  if (i == -1) {
    return padded;
  }
  return padded.substring(0, i);
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

ffi.Pointer<ssl.EVP_PKEY> _importJwkRsaPrivateOrPublicKey(
  JsonWebKey jwk, {
  bool isPrivateKey,
  String expectedAlg,
  String expectedUse,
}) {
  assert(isPrivateKey != null);
  assert(expectedAlg != null);

  final scope = _Scope();
  try {
    void checkJwk(bool condition, String prop, String message) =>
        _checkData(condition, message: 'JWK property "$prop" $message');

    checkJwk(jwk.kty == 'RSA', 'kty', 'must be "RSA"');
    checkJwk(
      jwk.alg == null || jwk.alg == expectedAlg,
      'alg',
      'must be "$expectedAlg", if present',
    );
    checkJwk(
      jwk.use == null || jwk.use == expectedUse,
      'use',
      'must be "$expectedUse", if present',
    );

    // TODO: Consider rejecting keys with key_ops inconsistent with isPrivateKey
    //       See also JWK import logic for EC keys

    ffi.Pointer<ssl.BIGNUM> readBN(String value, String prop) {
      final bin = _jwkDecodeBase64UrlNoPadding(value, prop);
      checkJwk(bin.length != 0, prop, 'must not be empty');
      checkJwk(
        bin.length == 1 || bin[0] != 0,
        prop,
        'must not have leading zeros',
      );
      return scope.create(
        () => ssl.BN_bin2bn(scope.dataAsPointer(bin), bin.length, ffi.nullptr),
        ssl.BN_free,
      );
    }

    final rsa = scope.create(ssl.RSA_new, ssl.RSA_free);

    final n = readBN(jwk.n, 'n');
    final e = readBN(jwk.e, 'e');
    _checkOpIsOne(ssl.RSA_set0_key(rsa, n, e, ffi.nullptr));
    scope.move(n); // ssl.RSA_set0_key takes ownership
    scope.move(e);

    if (isPrivateKey) {
      // The "p", "q", "dp", "dq", and "qi" properties are optional in the JWA
      // spec. However they are required by Chromium's WebCrypto implementation.
      final d = readBN(jwk.d, 'd');
      // If present properties p,q,dp,dq,qi enable optional optimizations, see:
      // https://tools.ietf.org/html/rfc7518#section-6.3.2
      // However, these are required by Chromes Web Crypto implementation:
      // https://chromium.googlesource.com/chromium/src/+/43d62c50b705f88c67b14539e91fd8fd017f70c4/components/webcrypto/algorithms/rsa.cc#82
      // They are also required by Web Crypto implementation in Firefox:
      // https://hg.mozilla.org/mozilla-central/file/38e6ad5fd7535be88e432075f76ec4a2dc294672/dom/crypto/CryptoKey.cpp#l588
      // We follow this precedence because (a) having optimizations is nice,
      // and, (b) following Chromes/Firefox behavior is safe.
      // Notice, we can choose to support this in the future without breaking
      // the public API.
      final p = readBN(jwk.p, 'p');
      final q = readBN(jwk.q, 'q');
      final dp = readBN(jwk.dp, 'dp');
      final dq = readBN(jwk.dq, 'dq');
      final qi = readBN(jwk.qi, 'qi');

      _checkOpIsOne(ssl.RSA_set0_key(rsa, ffi.nullptr, ffi.nullptr, d));
      scope.move(d); // ssl.RSA_set0_key takes ownership

      _checkOpIsOne(ssl.RSA_set0_factors(rsa, p, q));
      scope.move(p); // ssl.RSA_set0_factors takes ownership
      scope.move(q);

      _checkOpIsOne(ssl.RSA_set0_crt_params(rsa, dp, dq, qi));
      scope.move(dp); // ssl.RSA_set0_crt_params takes ownership
      scope.move(dq);
      scope.move(qi);

      // Notice that 'jwk.oth' isn't supported by Chrome:
      // https://chromium.googlesource.com/chromium/src/+/43d62c50b705f88c67b14539e91fd8fd017f70c4/components/webcrypto/algorithms/rsa.cc#31
      // This also appears to be ignored by Firefox:
      // https://hg.mozilla.org/mozilla-central/file/38e6ad5fd7535be88e432075f76ec4a2dc294672/dom/crypto/CryptoKey.cpp#l588
      // Thus, we follow Chrome and ignore property.
    }

    _checkDataIsOne(ssl.RSA_check_key(rsa), fallback: 'invalid RSA key');

    final key = scope.create(ssl.EVP_PKEY_new, ssl.EVP_PKEY_free);
    _checkOpIsOne(ssl.EVP_PKEY_set1_RSA(key, rsa));

    return scope.move(key);
  } finally {
    scope.release();
  }
}

Map<String, dynamic> _exportJwkRsaPrivateOrPublicKey(
  ffi.Pointer<ssl.EVP_PKEY> key, {
  bool isPrivateKey,
  String jwkAlg,
  String jwkUse,
}) {
  assert(isPrivateKey != null);
  assert(jwkUse != null);
  assert(jwkAlg != null);

  final scope = _Scope();
  try {
    final rsa = ssl.EVP_PKEY_get0_RSA(key);
    _checkOp(rsa.address != 0, fallback: 'internal key type error');

    String encodeBN(ffi.Pointer<ssl.BIGNUM> bn) {
      final N = ssl.BN_num_bytes(bn);
      final result = _withOutPointer(N, (ffi.Pointer<ssl.Bytes> p) {
        _checkOpIsOne(ssl.BN_bn2bin_padded(p, N, bn));
      });
      assert(result.length == 1 || result[0] != 0);
      return _jwkEncodeBase64UrlNoPadding(result);
    }

    // Public key parameters
    final n = scope.allocate<ffi.Pointer<ssl.BIGNUM>>();
    final e = scope.allocate<ffi.Pointer<ssl.BIGNUM>>();
    ssl.RSA_get0_key(rsa, n, e, ffi.nullptr);

    if (!isPrivateKey) {
      return JsonWebKey(
        kty: 'RSA',
        use: jwkUse,
        alg: jwkAlg,
        n: encodeBN(n.value),
        e: encodeBN(e.value),
      ).toJson();
    }

    final d = scope.allocate<ffi.Pointer<ssl.BIGNUM>>();
    ssl.RSA_get0_key(rsa, ffi.nullptr, ffi.nullptr, d);

    // p, q, dp, dq, qi is optional in:
    // // https://tools.ietf.org/html/rfc7518#section-6.3.2
    // but explicitly required when exporting in Web Crypto.
    final p = scope.allocate<ffi.Pointer<ssl.BIGNUM>>();
    final q = scope.allocate<ffi.Pointer<ssl.BIGNUM>>();
    ssl.RSA_get0_factors(rsa, p, q);

    final dp = scope.allocate<ffi.Pointer<ssl.BIGNUM>>();
    final dq = scope.allocate<ffi.Pointer<ssl.BIGNUM>>();
    final qi = scope.allocate<ffi.Pointer<ssl.BIGNUM>>();
    ssl.RSA_get0_crt_params(rsa, dp, dq, qi);

    return JsonWebKey(
      kty: 'RSA',
      use: jwkUse,
      alg: jwkAlg,
      n: encodeBN(n.value),
      e: encodeBN(e.value),
      d: encodeBN(d.value),
      p: encodeBN(p.value),
      q: encodeBN(q.value),
      dp: encodeBN(dp.value),
      dq: encodeBN(dq.value),
      qi: encodeBN(qi.value),
    ).toJson();
  } finally {
    scope.release();
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

//---------------------- EC Helpers

/// Get `ssl.NID_...` from BoringSSL matching the given [curve].
int _ecCurveToNID(EllipticCurve curve) {
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

/// Get [EllipticCurve] from matching BoringSSL `ssl.NID_...`.
EllipticCurve _ecCurveFromNID(int nid) {
  assert(nid != null);

  if (nid == ssl.NID_X9_62_prime256v1) {
    return EllipticCurve.p256;
  }
  if (nid == ssl.NID_secp384r1) {
    return EllipticCurve.p384;
  }
  if (nid == ssl.NID_secp521r1) {
    return EllipticCurve.p521;
  }
  // This should never happen!
  throw _OperationError('internal error detecting curve');
}

String _ecCurveToJwkCrv(EllipticCurve curve) {
  ArgumentError.checkNotNull(curve, 'curve');

  if (curve == EllipticCurve.p256) {
    return 'P-256';
  }
  if (curve == EllipticCurve.p384) {
    return 'P-384';
  }
  if (curve == EllipticCurve.p521) {
    return 'P-521';
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
  _checkData(_ecCurveToNID(curve) == nid, message: 'incorrect elliptic curve');
}

ffi.Pointer<ssl.EVP_PKEY> _importPkcs8EcPrivateKey(
  List<int> keyData,
  EllipticCurve curve,
) {
  final key = _withDataAsCBS(keyData, ssl.EVP_parse_private_key);
  _checkData(key.address != 0, fallback: 'unable to parse key');

  try {
    _validateEllipticCurveKey(key, curve);
    return key;
  } catch (_) {
    // We only free key if an exception/error was thrown
    ssl.EVP_PKEY_free(key);
    rethrow;
  }
}

ffi.Pointer<ssl.EVP_PKEY> _importSpkiEcPublicKey(
  List<int> keyData,
  EllipticCurve curve,
) {
  // TODO: When calling EVP_parse_public_key it might wise to check that CBS_len(cbs) == 0 is true afterwards
  // otherwise it might be that all of the contents of the key was not consumed and we should throw
  // a FormatException. Notice that this the case for private/public keys, and RSA keys.
  final key = _withDataAsCBS(keyData, ssl.EVP_parse_public_key);
  _checkData(key.address != 0, fallback: 'unable to parse key');

  try {
    _validateEllipticCurveKey(key, curve);

    return key;
  } catch (_) {
    // We only free key if an exception/error was thrown
    ssl.EVP_PKEY_free(key);
    rethrow;
  }
}

ffi.Pointer<ssl.EVP_PKEY> _importJwkEcPrivateOrPublicKey(
  JsonWebKey jwk,
  EllipticCurve curve, {
  bool isPrivateKey,
  String expectedUse,
  String expectedAlg, // may be null, if 'alg' property isn't validated (ECDH)
}) {
  assert(isPrivateKey != null);
  assert(expectedUse != null);

  _checkData(
    jwk.kty == 'EC',
    message: 'expected a elliptic-curve key, JWK property "kty" must be "EC"',
  );
  if (isPrivateKey) {
    _checkData(
      jwk.d != null,
      message: 'expected a private key, JWK property "d" is missing',
    );
  } else {
    _checkData(
      jwk.d == null,
      message: 'expected a public key, JWK property "d" is present',
    );
  }

  final crv = _ecCurveToJwkCrv(curve);
  _checkData(jwk.crv == crv, message: 'JWK property "crv" is not "$crv"');

  _checkData(expectedAlg == null || jwk.alg == null || jwk.alg == expectedAlg,
      message: 'JWK property "alg" should be "$expectedAlg", if present');

  _checkData(jwk.use == null || jwk.use == expectedUse,
      message: 'JWK property "use" should be "$expectedUse", if present');

  // TODO: Reject keys with key_ops in inconsistent with isPrivateKey
  //       Also in the js implementation...

  final scope = _Scope();
  try {
    final ec = ssl.EC_KEY_new_by_curve_name(_ecCurveToNID(curve));
    _checkOp(ec.address != 0, fallback: 'internal failure to use curve');
    scope.defer(() => ssl.EC_KEY_free(ec));

    // We expect parameters to have this size
    final paramSize = _numBitsToBytes(ssl.EC_GROUP_get_degree(
      ssl.EC_KEY_get0_group(ec),
    ));

    // Utility to decode a JWK parameter.
    ffi.Pointer<ssl.BIGNUM> decodeParam(String val, String prop) {
      final bytes = _jwkDecodeBase64UrlNoPadding(val, prop);
      _checkData(
        bytes.length == paramSize,
        message: 'JWK property "$prop" should hold $paramSize bytes',
      );
      final bn = ssl.BN_bin2bn(
        scope.dataAsPointer(bytes),
        bytes.length,
        ffi.nullptr,
      );
      _checkData(bn.address != 0);
      scope.defer(() => ssl.BN_free(bn));
      return bn;
    }

    // Note: ideally we wouldn't throw data errors in case of internal errors
    _checkDataIsOne(
      ssl.EC_KEY_set_public_key_affine_coordinates(
        ec,
        decodeParam(jwk.x, 'x'),
        decodeParam(jwk.y, 'y'),
      ),
      fallback: 'invalid EC key',
    );

    if (isPrivateKey) {
      _checkDataIsOne(
        ssl.EC_KEY_set_private_key(ec, decodeParam(jwk.d, 'd')),
        fallback: 'invalid EC key',
      );
    }

    _checkDataIsOne(ssl.EC_KEY_check_key(ec), fallback: 'invalid EC key');

    // Wrap with an EVP_KEY
    final key = scope.create(ssl.EVP_PKEY_new, ssl.EVP_PKEY_free);
    _checkOpIsOne(ssl.EVP_PKEY_set1_EC_KEY(key, ec));

    return scope.move(key);
  } finally {
    scope.release();
  }
}

ffi.Pointer<ssl.EVP_PKEY> _importRawEcPublicKey(
  List<int> keyData,
  EllipticCurve curve,
) {
  // See: https://chromium.googlesource.com/chromium/src/+/43d62c50b705f88c67b14539e91fd8fd017f70c4/components/webcrypto/algorithms/ec.cc#332

  // Create EC_KEY for the curve
  final ec = ssl.EC_KEY_new_by_curve_name(_ecCurveToNID(curve));
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
        return key;
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

Uint8List _exportRawEcPublicKey(ffi.Pointer<ssl.EVP_PKEY> key) {
  final ec = ssl.EVP_PKEY_get0_EC_KEY(key);
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

Map<String, dynamic> _exportJwkEcPrivateOrPublicKey(
  ffi.Pointer<ssl.EVP_PKEY> key, {
  bool isPrivateKey,
  String jwkUse,
}) {
  assert(isPrivateKey != null);
  assert(jwkUse != null);

  final scope = _Scope();
  try {
    final ec = ssl.EVP_PKEY_get0_EC_KEY(key);
    _checkOp(ec.address != 0, fallback: 'internal key type invariant error');

    final group = ssl.EC_KEY_get0_group(ec);
    final curve = _ecCurveFromNID(ssl.EC_GROUP_get_curve_name(group));

    // Determine byte size used for encoding params
    final paramSize = _numBitsToBytes(ssl.EC_GROUP_get_degree(group));

    final x = scope.create(ssl.BN_new, ssl.BN_free);
    final y = scope.create(ssl.BN_new, ssl.BN_free);

    _checkOpIsOne(ssl.EC_POINT_get_affine_coordinates_GFp(
      group,
      ssl.EC_KEY_get0_public_key(ec),
      x,
      y,
      ffi.nullptr,
    ));

    final xAsBytes = _withOutPointer(paramSize, (ffi.Pointer<ssl.Bytes> p) {
      _checkOpIsOne(ssl.BN_bn2bin_padded(p, paramSize, x));
    });
    final yAsBytes = _withOutPointer(paramSize, (ffi.Pointer<ssl.Bytes> p) {
      _checkOpIsOne(ssl.BN_bn2bin_padded(p, paramSize, y));
    });

    Uint8List dAsBytes;
    if (isPrivateKey) {
      final d = ssl.EC_KEY_get0_private_key(ec);
      dAsBytes = _withOutPointer(paramSize, (ffi.Pointer<ssl.Bytes> p) {
        _checkOpIsOne(ssl.BN_bn2bin_padded(p, paramSize, d));
      });
    }

    return JsonWebKey(
      kty: 'EC',
      use: jwkUse,
      crv: _ecCurveToJwkCrv(curve),
      x: _jwkEncodeBase64UrlNoPadding(xAsBytes),
      y: _jwkEncodeBase64UrlNoPadding(yAsBytes),
      d: isPrivateKey ? _jwkEncodeBase64UrlNoPadding(dAsBytes) : null,
    ).toJson();
  } finally {
    scope.release();
  }
}

KeyPair<ffi.Pointer<ssl.EVP_PKEY>, ffi.Pointer<ssl.EVP_PKEY>>
    _generateEcKeyPair(
  EllipticCurve curve,
) {
  final scope = _Scope();
  try {
    final ecPriv = ssl.EC_KEY_new_by_curve_name(_ecCurveToNID(curve));
    _checkOp(ecPriv.address != 0, fallback: 'internal failure to use curve');
    scope.defer(() => ssl.EC_KEY_free(ecPriv));

    _checkOpIsOne(ssl.EC_KEY_generate_key(ecPriv));

    final privKey = scope.create(ssl.EVP_PKEY_new, ssl.EVP_PKEY_free);
    _checkOpIsOne(ssl.EVP_PKEY_set1_EC_KEY(privKey, ecPriv));

    final ecPub = ssl.EC_KEY_new_by_curve_name(_ecCurveToNID(curve));
    _checkOp(ecPub.address != 0);
    scope.defer(() => ssl.EC_KEY_free(ecPub));
    _checkOpIsOne(ssl.EC_KEY_set_public_key(
      ecPub,
      ssl.EC_KEY_get0_public_key(ecPriv),
    ));

    final pubKey = scope.create(ssl.EVP_PKEY_new, ssl.EVP_PKEY_free);
    _checkOpIsOne(ssl.EVP_PKEY_set1_EC_KEY(pubKey, ecPub));

    return _KeyPair(
      privateKey: scope.move(privKey),
      publicKey: scope.move(pubKey),
    );
  } finally {
    scope.release();
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
// Note: Before adding new hash implementations, make sure to update all the
//       places that does if (hash == Hash.sha256) ...

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

String _hmacJwkAlgFromHash(_Hash hash) {
  if (hash == Hash.sha1) {
    return 'HS1';
  }
  if (hash == Hash.sha256) {
    return 'HS256';
  }
  if (hash == Hash.sha384) {
    return 'HS384';
  }
  if (hash == Hash.sha512) {
    return 'HS512';
  }
  assert(false); // This should never happen!
  throw UnsupportedError('hash is not supported');
}

Future<HmacSecretKey> hmacSecretKey_importRawKey(
  List<int> keyData,
  Hash hash, {
  int length,
}) async {
  return _HmacSecretKey(
    _asUint8ListZeroedToBitLength(keyData, length),
    _Hash.fromHash(hash),
  );
}

Future<HmacSecretKey> hmacSecretKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  Hash hash, {
  int length,
}) async {
  ArgumentError.checkNotNull(jwk, 'jwk');
  ArgumentError.checkNotNull(hash, 'hash');

  final h = _Hash.fromHash(hash);
  final k = JsonWebKey.fromJson(jwk);

  void checkJwk(bool condition, String prop, String message) =>
      _checkData(condition, message: 'JWK property "$prop" $message');

  checkJwk(k.kty == 'oct', 'kty', 'must be "oct"');
  checkJwk(k.k != null, 'k', 'must be present');
  checkJwk(k.use == null || k.use == 'sig', 'use', 'must be "sig", if present');
  final expectedAlg = _hmacJwkAlgFromHash(h);
  checkJwk(
    k.alg == null || k.alg == expectedAlg,
    'alg',
    'must be "$expectedAlg"',
  );

  final keyData = _jwkDecodeBase64UrlNoPadding(k.k, 'k');

  return hmacSecretKey_importRawKey(keyData, hash, length: length);
}

Future<HmacSecretKey> hmacSecretKey_generateKey(Hash hash, {int length}) async {
  final h = _Hash.fromHash(hash);
  length ??= ssl.EVP_MD_size(h.MD) * 8;
  final keyData = Uint8List((length / 8).ceil());
  fillRandomBytes(keyData);

  return _HmacSecretKey(
    _asUint8ListZeroedToBitLength(keyData, length),
    h,
  );
}

class _HmacSecretKey implements HmacSecretKey {
  final _Hash _hash;
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
        _checkOp(ssl.HMAC_Init_ex(ctx, p, n, _hash.MD, ffi.nullptr) == 1);
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
  Future<Map<String, dynamic>> exportJsonWebKey() async {
    return JsonWebKey(
      kty: 'oct',
      use: 'sig',
      alg: _hmacJwkAlgFromHash(_hash),
      k: _jwkEncodeBase64UrlNoPadding(_keyData),
    ).toJson();
  }

  @override
  Future<Uint8List> exportRawKey() async {
    return Uint8List.fromList(_keyData);
  }
}

//---------------------- RSASSA_PKCS1_v1_5

String _rsassaPkcs1V15JwkAlgFromHash(_Hash hash) {
  if (hash == Hash.sha1) {
    return 'RS1';
  }
  if (hash == Hash.sha256) {
    return 'RS256';
  }
  if (hash == Hash.sha384) {
    return 'RS384';
  }
  if (hash == Hash.sha512) {
    return 'RS512';
  }
  assert(false); // This should never happen!
  throw UnsupportedError('hash is not supported');
}

Future<RsassaPkcs1V15PrivateKey> rsassaPkcs1V15PrivateKey_importPkcs8Key(
  List<int> keyData,
  Hash hash,
) async {
  // Get hash first, to avoid a leak of EVP_PKEY if _Hash.fromHash throws
  final h = _Hash.fromHash(hash);
  return _RsassaPkcs1V15PrivateKey(_importPkcs8RsaPrivateKey(keyData), h);
}

Future<RsassaPkcs1V15PrivateKey> rsassaPkcs1V15PrivateKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  Hash hash,
) async {
  // Get hash first, to avoid a leak of EVP_PKEY if _Hash.fromHash throws
  final h = _Hash.fromHash(hash);
  return _RsassaPkcs1V15PrivateKey(
    _importJwkRsaPrivateOrPublicKey(
      JsonWebKey.fromJson(jwk),
      isPrivateKey: true,
      expectedUse: 'sig',
      expectedAlg: _rsassaPkcs1V15JwkAlgFromHash(h),
    ),
    h,
  );
}

Future<KeyPair<RsassaPkcs1V15PrivateKey, RsassaPkcs1V15PublicKey>>
    rsassaPkcs1V15PrivateKey_generateKey(
  int modulusLength,
  BigInt publicExponent,
  Hash hash,
) async {
  // Get hash first, to avoid a leak of EVP_PKEY if _Hash.fromHash throws
  final h = _Hash.fromHash(hash);
  final keys = _generateRsaKeyPair(modulusLength, publicExponent);
  return _KeyPair(
    privateKey: _RsassaPkcs1V15PrivateKey(keys.privateKey, h),
    publicKey: _RsassaPkcs1V15PublicKey(keys.publicKey, h),
  );
}

Future<RsassaPkcs1V15PublicKey> rsassaPkcs1V15PublicKey_importSpkiKey(
  List<int> keyData,
  Hash hash,
) async {
  // Get hash first, to avoid a leak of EVP_PKEY if _Hash.fromHash throws
  final h = _Hash.fromHash(hash);
  return _RsassaPkcs1V15PublicKey(_importSpkiRsaPublicKey(keyData), h);
}

Future<RsassaPkcs1V15PublicKey> rsassaPkcs1V15PublicKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  Hash hash,
) async {
  // Get hash first, to avoid a leak of EVP_PKEY if _Hash.fromHash throws
  final h = _Hash.fromHash(hash);
  return _RsassaPkcs1V15PublicKey(
    _importJwkRsaPrivateOrPublicKey(
      JsonWebKey.fromJson(jwk),
      isPrivateKey: false,
      expectedUse: 'sig',
      expectedAlg: _rsassaPkcs1V15JwkAlgFromHash(h),
    ),
    h,
  );
}

class _RsassaPkcs1V15PrivateKey
    with _Disposable
    implements RsassaPkcs1V15PrivateKey {
  final ffi.Pointer<ssl.EVP_PKEY> _key;
  final _Hash _hash;

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
          ssl.EVP_DigestSignInit(ctx, pctx, _hash.MD, ffi.nullptr, _key),
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
  Future<Map<String, dynamic>> exportJsonWebKey() async =>
      _exportJwkRsaPrivateOrPublicKey(
        _key,
        isPrivateKey: true,
        jwkAlg: _rsassaPkcs1V15JwkAlgFromHash(_hash),
        jwkUse: 'sig',
      );

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
  final _Hash _hash;

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
          ssl.EVP_DigestVerifyInit(ctx, pctx, _hash.MD, ffi.nullptr, _key),
        );
        _checkOpIsOne(
          ssl.EVP_PKEY_CTX_set_rsa_padding(pctx.value, ssl.RSA_PKCS1_PADDING),
        );
        await _streamToUpdate(data, ctx, ssl.EVP_DigestVerifyUpdate);
        return _withDataAsPointer(signature, (ffi.Pointer<ssl.Bytes> p) {
          final result = ssl.EVP_DigestVerifyFinal(ctx, p, signature.length);
          if (result != 1) {
            // TODO: We should always clear errors, when returning from any
            //       function that uses BoringSSL.
            // Note: In this case we could probably assert that error is just
            //       signature related.
            ssl.ERR_clear_error();
          }
          return result == 1;
        });
      });
    });
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async =>
      _exportJwkRsaPrivateOrPublicKey(
        _key,
        isPrivateKey: false,
        jwkAlg: _rsassaPkcs1V15JwkAlgFromHash(_hash),
        jwkUse: 'sig',
      );

  @override
  Future<Uint8List> exportSpkiKey() async {
    return _withOutCBB((cbb) {
      _checkOp(ssl.EVP_marshal_public_key(cbb, _key) == 1);
    });
  }
}

//---------------------- RSA-PSS

String _rsaPssJwkAlgFromHash(_Hash hash) {
  if (hash == Hash.sha1) {
    return 'PS1';
  }
  if (hash == Hash.sha256) {
    return 'PS256';
  }
  if (hash == Hash.sha384) {
    return 'PS384';
  }
  if (hash == Hash.sha512) {
    return 'PS512';
  }
  assert(false); // This should never happen!
  throw UnsupportedError('hash is not supported');
}

Future<RsaPssPrivateKey> rsaPssPrivateKey_importPkcs8Key(
  List<int> keyData,
  Hash hash,
) async {
  // Get hash first, to avoid a leak of EVP_PKEY if _Hash.fromHash throws
  final h = _Hash.fromHash(hash);
  return _RsaPssPrivateKey(_importPkcs8RsaPrivateKey(keyData), h);
}

Future<RsaPssPrivateKey> rsaPssPrivateKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  Hash hash,
) async {
  // Get hash first, to avoid a leak of EVP_PKEY if _Hash.fromHash throws
  final h = _Hash.fromHash(hash);
  return _RsaPssPrivateKey(
    _importJwkRsaPrivateOrPublicKey(
      JsonWebKey.fromJson(jwk),
      isPrivateKey: true,
      expectedUse: 'sig',
      expectedAlg: _rsaPssJwkAlgFromHash(h),
    ),
    h,
  );
}

Future<KeyPair<RsaPssPrivateKey, RsaPssPublicKey>> rsaPssPrivateKey_generateKey(
  int modulusLength,
  BigInt publicExponent,
  Hash hash,
) async {
  // Get hash first, to avoid a leak of EVP_PKEY if _Hash.fromHash throws
  final h = _Hash.fromHash(hash);
  final keys = _generateRsaKeyPair(modulusLength, publicExponent);
  return _KeyPair(
    privateKey: _RsaPssPrivateKey(keys.privateKey, h),
    publicKey: _RsaPssPublicKey(keys.publicKey, h),
  );
}

Future<RsaPssPublicKey> rsaPssPublicKey_importSpkiKey(
  List<int> keyData,
  Hash hash,
) async {
  // Get hash first, to avoid a leak of EVP_PKEY if _Hash.fromHash throws
  final h = _Hash.fromHash(hash);
  return _RsaPssPublicKey(_importSpkiRsaPublicKey(keyData), h);
}

Future<RsaPssPublicKey> rsaPssPublicKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  Hash hash,
) async {
  // Get hash first, to avoid a leak of EVP_PKEY if _Hash.fromHash throws
  final h = _Hash.fromHash(hash);
  return _RsaPssPublicKey(
    _importJwkRsaPrivateOrPublicKey(
      JsonWebKey.fromJson(jwk),
      isPrivateKey: false,
      expectedUse: 'sig',
      expectedAlg: _rsaPssJwkAlgFromHash(h),
    ),
    h,
  );
}

class _RsaPssPrivateKey with _Disposable implements RsaPssPrivateKey {
  final ffi.Pointer<ssl.EVP_PKEY> _key;
  final _Hash _hash;

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
          ssl.EVP_DigestSignInit(ctx, pctx, _hash.MD, ffi.nullptr, _key),
        );
        _checkOpIsOne(ssl.EVP_PKEY_CTX_set_rsa_padding(
          pctx.value,
          ssl.RSA_PKCS1_PSS_PADDING,
        ));
        _checkDataIsOne(ssl.EVP_PKEY_CTX_set_rsa_pss_saltlen(
          pctx.value,
          saltLength,
        ));
        _checkDataIsOne(ssl.EVP_PKEY_CTX_set_rsa_mgf1_md(pctx.value, _hash.MD));
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
  Future<Map<String, dynamic>> exportJsonWebKey() async =>
      _exportJwkRsaPrivateOrPublicKey(
        _key,
        isPrivateKey: true,
        jwkUse: 'sig',
        jwkAlg: _rsaPssJwkAlgFromHash(_hash),
      );

  @override
  Future<Uint8List> exportPkcs8Key() async {
    return _withOutCBB((cbb) {
      _checkOp(ssl.EVP_marshal_private_key(cbb, _key) == 1);
    });
  }
}

class _RsaPssPublicKey with _Disposable implements RsaPssPublicKey {
  final ffi.Pointer<ssl.EVP_PKEY> _key;
  final _Hash _hash;

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
          ssl.EVP_DigestVerifyInit(ctx, pctx, _hash.MD, ffi.nullptr, _key),
        );
        _checkOpIsOne(ssl.EVP_PKEY_CTX_set_rsa_padding(
          pctx.value,
          ssl.RSA_PKCS1_PSS_PADDING,
        ));
        _checkDataIsOne(ssl.EVP_PKEY_CTX_set_rsa_pss_saltlen(
          pctx.value,
          saltLength,
        ));
        _checkDataIsOne(ssl.EVP_PKEY_CTX_set_rsa_mgf1_md(pctx.value, _hash.MD));
        await _streamToUpdate(data, ctx, ssl.EVP_DigestVerifyUpdate);
        return _withDataAsPointer(signature, (ffi.Pointer<ssl.Bytes> p) {
          final result = ssl.EVP_DigestVerifyFinal(ctx, p, signature.length);
          if (result != 1) {
            // TODO: We should always clear errors, when returning from any
            //       function that uses BoringSSL.
            // Note: In this case we could probably assert that error is just
            //       signature related.
            ssl.ERR_clear_error();
          }
          return result == 1;
        });
      });
    });
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async =>
      _exportJwkRsaPrivateOrPublicKey(
        _key,
        isPrivateKey: false,
        jwkUse: 'sig',
        jwkAlg: _rsaPssJwkAlgFromHash(_hash),
      );

  @override
  Future<Uint8List> exportSpkiKey() async {
    return _withOutCBB((cbb) {
      _checkOp(ssl.EVP_marshal_public_key(cbb, _key) == 1);
    });
  }
}

//---------------------- ECDSA

/// Get valid value for `jwk.alg` property given an [EllipticCurve] for ECDSA.
String _ecdsaCurveToJwkAlg(EllipticCurve curve) {
  ArgumentError.checkNotNull(curve, 'curve');

  if (curve == EllipticCurve.p256) {
    return 'ES256';
  }
  if (curve == EllipticCurve.p384) {
    return 'ES384';
  }
  if (curve == EllipticCurve.p521) {
    // ES512 means P-521 with SHA-512 (not a typo)
    return 'ES512';
  }
  // This should never happen!
  throw UnsupportedError('curve "$curve" is not supported');
}

Future<EcdsaPrivateKey> ecdsaPrivateKey_importPkcs8Key(
  List<int> keyData,
  EllipticCurve curve,
) async =>
    _EcdsaPrivateKey(_importPkcs8EcPrivateKey(keyData, curve));

Future<EcdsaPrivateKey> ecdsaPrivateKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  EllipticCurve curve,
) async =>
    _EcdsaPrivateKey(_importJwkEcPrivateOrPublicKey(
      JsonWebKey.fromJson(jwk),
      curve,
      isPrivateKey: true,
      expectedUse: 'sig',
      expectedAlg: _ecdsaCurveToJwkAlg(curve),
    ));

Future<KeyPair<EcdsaPrivateKey, EcdsaPublicKey>> ecdsaPrivateKey_generateKey(
  EllipticCurve curve,
) async {
  final p = _generateEcKeyPair(curve);
  return _KeyPair(
    privateKey: _EcdsaPrivateKey(p.privateKey),
    publicKey: _EcdsaPublicKey(p.publicKey),
  );
}

Future<EcdsaPublicKey> ecdsaPublicKey_importRawKey(
  List<int> keyData,
  EllipticCurve curve,
) async =>
    _EcdsaPublicKey(_importRawEcPublicKey(keyData, curve));

Future<EcdsaPublicKey> ecdsaPublicKey_importSpkiKey(
  List<int> keyData,
  EllipticCurve curve,
) async =>
    _EcdsaPublicKey(_importSpkiEcPublicKey(keyData, curve));

Future<EcdsaPublicKey> ecdsaPublicKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  EllipticCurve curve,
) async =>
    _EcdsaPublicKey(_importJwkEcPrivateOrPublicKey(
      JsonWebKey.fromJson(jwk),
      curve,
      isPrivateKey: false,
      expectedUse: 'sig',
      expectedAlg: _ecdsaCurveToJwkAlg(curve),
    ));

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

  if (N * 2 != signature.length) {
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
  Future<Map<String, dynamic>> exportJsonWebKey() async =>
      _exportJwkEcPrivateOrPublicKey(_key, isPrivateKey: true, jwkUse: 'sig');

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
          if (result != 1) {
            // TODO: We should always clear errors, when returning from any
            //       function that uses BoringSSL.
            // Note: In this case we could probably assert that error is just
            //       signature related.
            ssl.ERR_clear_error();
          }
          return result == 1;
        });
      });
    });
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async =>
      _exportJwkEcPrivateOrPublicKey(_key, isPrivateKey: false, jwkUse: 'sig');

  @override
  Future<Uint8List> exportRawKey() async => _exportRawEcPublicKey(_key);

  @override
  Future<Uint8List> exportSpkiKey() async {
    return _withOutCBB((cbb) {
      _checkOp(ssl.EVP_marshal_public_key(cbb, _key) == 1);
    });
  }
}

//---------------------- RSA-OAEP

String _rsaOaepJwkAlgFromHash(_Hash hash) {
  if (hash == Hash.sha1) {
    return 'RSA-OAEP';
  }
  if (hash == Hash.sha256) {
    return 'RSA-OAEP-256';
  }
  if (hash == Hash.sha384) {
    return 'RSA-OAEP-384';
  }
  if (hash == Hash.sha512) {
    return 'RSA-OAEP-512';
  }
  assert(false); // This should never happen!
  throw UnsupportedError('hash is not supported');
}

Future<RsaOaepPrivateKey> rsaOaepPrivateKey_importPkcs8Key(
  List<int> keyData,
  Hash hash,
) async {
  // Get hash first, to avoid a leak of EVP_PKEY if _Hash.fromHash throws
  final h = _Hash.fromHash(hash);
  return _RsaOaepPrivateKey(_importPkcs8RsaPrivateKey(keyData), h);
}

Future<RsaOaepPrivateKey> rsaOaepPrivateKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  Hash hash,
) async {
  // Get hash first, to avoid a leak of EVP_PKEY if _Hash.fromHash throws
  final h = _Hash.fromHash(hash);
  return _RsaOaepPrivateKey(
    _importJwkRsaPrivateOrPublicKey(
      JsonWebKey.fromJson(jwk),
      isPrivateKey: true,
      expectedUse: 'enc',
      expectedAlg: _rsaOaepJwkAlgFromHash(h),
    ),
    h,
  );
}

Future<KeyPair<RsaOaepPrivateKey, RsaPssPublicKey>>
    rsaOaepPrivateKey_generateKey(
  int modulusLength,
  BigInt publicExponent,
  Hash hash,
) async {
  // Get hash first, to avoid a leak of EVP_PKEY if _Hash.fromHash throws
  final h = _Hash.fromHash(hash);
  final keys = _generateRsaKeyPair(modulusLength, publicExponent);
  return _KeyPair(
    privateKey: _RsaOaepPrivateKey(keys.privateKey, h),
    publicKey: _RsaPssPublicKey(keys.publicKey, h),
  );
}

Future<RsaOaepPublicKey> rsaOaepPublicKey_importSpkiKey(
  List<int> keyData,
  Hash hash,
) async {
  // Get hash first, to avoid a leak of EVP_PKEY if _Hash.fromHash throws
  final h = _Hash.fromHash(hash);
  return _RsaOaepPublicKey(_importSpkiRsaPublicKey(keyData), h);
}

Future<RsaOaepPublicKey> rsaOaepPublicKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  Hash hash,
) async {
  // Get hash first, to avoid a leak of EVP_PKEY if _Hash.fromHash throws
  final h = _Hash.fromHash(hash);
  return _RsaOaepPublicKey(
    _importJwkRsaPrivateOrPublicKey(
      JsonWebKey.fromJson(jwk),
      isPrivateKey: false,
      expectedUse: 'enc',
      expectedAlg: _rsaOaepJwkAlgFromHash(h),
    ),
    h,
  );
}

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
  final _Hash _hash;

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
      _hash.MD,
      ssl.EVP_PKEY_decrypt_init,
      ssl.EVP_PKEY_decrypt,
      data,
      label: label,
    );
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async =>
      _exportJwkRsaPrivateOrPublicKey(
        _key,
        isPrivateKey: true,
        jwkUse: 'enc',
        jwkAlg: _rsaOaepJwkAlgFromHash(_hash),
      );

  @override
  Future<Uint8List> exportPkcs8Key() async {
    return _withOutCBB((cbb) {
      _checkOp(ssl.EVP_marshal_private_key(cbb, _key) == 1);
    });
  }
}

class _RsaOaepPublicKey with _Disposable implements RsaOaepPublicKey {
  final ffi.Pointer<ssl.EVP_PKEY> _key;
  final _Hash _hash;

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
      _hash.MD,
      ssl.EVP_PKEY_encrypt_init,
      ssl.EVP_PKEY_encrypt,
      data,
      label: label,
    );
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async =>
      _exportJwkRsaPrivateOrPublicKey(
        _key,
        isPrivateKey: false,
        jwkUse: 'enc',
        jwkAlg: _rsaOaepJwkAlgFromHash(_hash),
      );

  @override
  Future<Uint8List> exportSpkiKey() async {
    return _withOutCBB((cbb) {
      _checkOp(ssl.EVP_marshal_public_key(cbb, _key) == 1);
    });
  }
}

//---------------------- AES Utilities

Uint8List _aesImportRawKey(List<int> keyData) {
  ArgumentError.checkNotNull(keyData, 'keyData');
  if (keyData.length == 24) {
    // 192-bit AES is intentionally unsupported, see https://crbug.com/533699
    // If not supported in Chrome, there is not reason to support it in Dart.
    throw UnsupportedError('192-bit AES keys are not supported');
  }
  if (keyData.length != 16 && keyData.length != 32) {
    throw FormatException('keyData for AES must be 128 or 256 bits');
  }
  return Uint8List.fromList(keyData);
}

Uint8List _aesImportJwkKey(
  Map<String, dynamic> jwk, {
  String expectedJwkAlgSuffix,
}) {
  assert(expectedJwkAlgSuffix != null);
  ArgumentError.checkNotNull(jwk, 'jwk');

  final k = JsonWebKey.fromJson(jwk);

  void checkJwk(bool condition, String prop, String message) =>
      _checkData(condition, message: 'JWK property "$prop" $message');

  checkJwk(k.kty == 'oct', 'kty', 'must be "oct"');
  checkJwk(k.k != null, 'k', 'must be present');
  checkJwk(k.use == null || k.use == 'enc', 'use', 'must be "enc", if present');

  final keyData = _jwkDecodeBase64UrlNoPadding(k.k, 'k');
  if (keyData.length == 24) {
    // 192-bit AES is intentionally unsupported, see https://crbug.com/533699
    // If not supported in Chrome, there is not reason to support it in Dart.
    throw UnsupportedError('192-bit AES keys are not supported');
  }
  checkJwk(keyData.length == 16 || keyData.length == 32, 'k',
      'must be a 128 or 256 bit key');

  final expectedAlgPrefix = keyData.length == 16 ? 'A128' : 'A256';
  final expectedAlg = expectedAlgPrefix + expectedJwkAlgSuffix;

  checkJwk(
    k.alg == null || k.alg == expectedAlg,
    'alg',
    'must be "$expectedAlg", if present',
  );

  return keyData;
}

Map<String, dynamic> _aesExportJwkKey(
  List<int> keyData, {
  String jwkAlgSuffix,
}) {
  assert(jwkAlgSuffix != null);
  assert(keyData.length == 16 || keyData.length == 32);
  final algPrefix = keyData.length == 16 ? 'A128' : 'A256';

  return JsonWebKey(
    kty: 'oct',
    use: 'enc',
    alg: algPrefix + jwkAlgSuffix,
    k: _jwkEncodeBase64UrlNoPadding(keyData),
  ).toJson();
}

Uint8List _aesGenerateKey(int length) {
  ArgumentError.checkNotNull(length, 'length');
  if (length == 192) {
    // 192-bit AES is intentionally unsupported, see https://crbug.com/533699
    // If not supported in Chrome, there is not reason to support it in Dart.
    throw UnsupportedError('192-bit AES keys are not supported');
  }
  if (length != 128 && length != 256) {
    throw FormatException('keyData for AES must be 128 or 256 bits');
  }
  final keyData = Uint8List(length ~/ 8);
  fillRandomBytes(keyData);
  return keyData;
}

//---------------------- AES-CTR

Future<AesCtrSecretKey> aesCtr_importRawKey(List<int> keyData) async =>
    _AesCtrSecretKey(_aesImportRawKey(keyData));

Future<AesCtrSecretKey> aesCtr_importJsonWebKey(
  Map<String, dynamic> jwk,
) async =>
    _AesCtrSecretKey(_aesImportJwkKey(
      jwk,
      expectedJwkAlgSuffix: 'CTR',
    ));

Future<AesCtrSecretKey> aesCtr_generateKey(int length) async =>
    _AesCtrSecretKey(_aesGenerateKey(length));

BigInt _parseBigEndian(List<int> data, [int bitLength]) {
  assert(data != null);
  bitLength ??= data.length * 8;
  assert(bitLength <= data.length * 8);

  // Find the index of the first byte we have to read
  final init = data.length - (bitLength / 8).ceil();
  // Find the remainder bits when reading the first byte
  final remainder_bits = bitLength % 8;
  // If there is any remainder bits, we make a copy and zero-out the rest of the
  // initial byte
  if (remainder_bits != 0) {
    data = Uint8List.fromList(data);
    data[init] &= ~(0xff << remainder_bits);
  }
  // Parse BigInt as big-endian integer.
  BigInt value = BigInt.from(0);
  for (int i = init; i < data.length; i++) {
    value = (value << 8) | BigInt.from(data[i] & 0xf);
  }
  return value;
}

Stream<Uint8List> _aesCtrEncryptOrDecrypt(
  Uint8List key,
  bool encrypt,
  Stream<List<int>> source,
  List<int> counter,
  int length,
) async* {
  // Heavily inspired by Chromium Web Crypto implementation, see:
  // https://chromium.googlesource.com/chromium/src/+/43d62c50b705f88c67b14539e91fd8fd017f70c4/components/webcrypto/algorithms/aes_ctr.cc#144

  final scope = _Scope();
  try {
    assert(counter.length == 16);
    assert(key.length == 16 || key.length == 32);
    final cipher =
        key.length == 16 ? ssl.EVP_aes_128_ctr() : ssl.EVP_aes_256_ctr();
    final blockSize = ssl.AES_BLOCK_SIZE;

    // Find the number of possible counter values, as the counter may not be
    // reused this will limit how much data we can process. If we get more data
    // than `blockSize * ctr_values`, Web Crypto will throw a `DataError`,
    // which we shall mirror by throwing a [FormatException].
    final ctr_values = BigInt.one << length;

    // Read the counter
    final ctr = _parseBigEndian(counter, length);

    // Number of bytes until wrap around. BoringSSL treats the counter as 128
    // bit counter that can be incremented. While web crypto specifies the
    // counter to be the first [length] bits of the `counter` parameter, and
    // the rest of the `counter` parameter is a nonce. Hence, when the counter
    // wraps around to zero, the left most `128 - length` bits should remain
    // static. Which is not the behavior BoringSSL implements. We can do this
    // with BoringSSL by managing the counter wrap-around manually. But to do
    // this we must track the number of blocks until wrap-around.
    var bytes_until_wraparound = (ctr_values - ctr) * BigInt.from(blockSize);

    // After wrap-around we cannot consume more than `ctr` blocks, or we'll
    // reuse the same counter value which is not allowed.
    var bytes_after_wraparound = ctr * BigInt.from(blockSize);

    final ctx = scope.create(ssl.EVP_CIPHER_CTX_new, ssl.EVP_CIPHER_CTX_free);
    _checkOpIsOne(ssl.EVP_CipherInit_ex(
      ctx,
      cipher,
      ffi.nullptr,
      scope.dataAsPointer(key),
      scope.dataAsPointer(counter),
      encrypt ? 1 : 0,
    ));

    const bufSize = 4096;

    // Allocate an input buffer
    final inBuf = scope.allocate<ffi.Uint8>(count: bufSize);
    final inData = inBuf.asTypedList(bufSize);
    final inBytes = inBuf.cast<ssl.Bytes>();
    // TODO: Migrate ssl.Bytes to ffi.Pointer<ffi.Uint8> (painful I know)

    // Allocate an output buffer, notice that BoringSSL says output cannot be
    // more than input size + blockSize - 1
    final outBuf = scope.allocate<ffi.Uint8>(count: bufSize + blockSize);
    final outData = outBuf.asTypedList(bufSize + blockSize);
    final outBytes = outBuf.cast<ssl.Bytes>();

    // Allocate and output length integer
    final outLen = scope.allocate<ffi.Int32>();

    // Process data from source
    var isBeforeWrapAround = true;
    await for (final data in source) {
      int offset = 0; // offset in data that we have consumed up-to.
      while (offset < data.length) {
        int M; // Number of bytes consumed in this iteration
        if (isBeforeWrapAround) {
          // Do not consume more bytes than allowed before wrap-around.
          M = math.min(bytes_until_wraparound.toInt(), data.length - offset);
          bytes_until_wraparound -= BigInt.from(M);
        } else {
          M = data.length - offset;
          // Do not consume more bytes than allowed after wrap-around
          if (bytes_after_wraparound.toInt() < M) {
            throw FormatException('input is too large for the counter length');
          }
          bytes_after_wraparound -= BigInt.from(M);
        }

        // Consume the first M bytes from data.
        int i = 0; // Number of bytes consumed, after offset
        while (i < M) {
          final N = math.min(M, bufSize);
          inData.setAll(0, data.skip(offset + i).take(N));

          _checkOpIsOne(ssl.EVP_CipherUpdate(
            ctx,
            outBytes,
            outLen,
            inBytes,
            N,
          ));
          if (outLen.value > 0) {
            yield outData.sublist(0, outLen.value);
          }
          i += N;
        }
        assert(i == M);
        offset += M;

        // Check if it's time to wrap-around
        if (isBeforeWrapAround && bytes_until_wraparound == BigInt.zero) {
          // Output final block of data before wrap-around
          _checkOpIsOne(ssl.EVP_CipherFinal_ex(ctx, outBytes, outLen));
          if (outLen.value > 0) {
            yield outData.sublist(0, outLen.value);
          }

          final counterWrappedAround = scope.dataAsPointer<ffi.Uint8>(counter);
          // Zero out the [length] right-most bits of [counterWrappedAround].
          final c = counterWrappedAround.asTypedList(16);
          final remainder_bits = length % 8;
          final counter_bytes = length ~/ 8;
          c.fillRange(c.length - counter_bytes, c.length, 0);
          if (remainder_bits != 0) {
            c[c.length - counter_bytes - 1] &= 0xff & (0xff << remainder_bits);
          }

          // Re-initialize the cipher context with counter wrapped around.
          _checkOpIsOne(ssl.EVP_CipherInit_ex(
            ctx,
            cipher,
            ffi.nullptr,
            scope.dataAsPointer(key),
            counterWrappedAround.cast<ssl.Bytes>(),
            encrypt ? 1 : 0,
          ));

          // Update state
          isBeforeWrapAround = false;
        }
      }
    }

    // Output final block
    _checkOpIsOne(ssl.EVP_CipherFinal_ex(ctx, outBytes, outLen));
    if (outLen.value > 0) {
      yield outData.sublist(0, outLen.value);
    }
  } finally {
    scope.release();
  }
}

class _AesCtrSecretKey implements AesCtrSecretKey {
  final Uint8List _key;
  _AesCtrSecretKey(this._key);

  void _checkArguments(
    List<int> counter,
    int length,
  ) {
    ArgumentError.checkNotNull(counter, 'counter');
    ArgumentError.checkNotNull(length, 'length');
    if (counter.length != 16) {
      throw ArgumentError.value(counter, 'counter', 'must be 16 bytes');
    }
    if (length <= 0 || 128 < length) {
      throw ArgumentError.value(length, 'length', 'must be between 1 and 128');
    }
  }

  @override
  Future<Uint8List> decryptBytes(
    List<int> data,
    List<int> counter,
    int length,
  ) async {
    ArgumentError.checkNotNull(data, 'data');
    _checkArguments(counter, length);
    return await _bufferStream(decryptStream(
      Stream.value(data),
      counter,
      length,
    ));
  }

  @override
  Stream<Uint8List> decryptStream(
    Stream<List<int>> data,
    List<int> counter,
    int length,
  ) {
    ArgumentError.checkNotNull(data, 'data');
    _checkArguments(counter, length);
    return _aesCtrEncryptOrDecrypt(_key, false, data, counter, length);
  }

  @override
  Future<Uint8List> encryptBytes(
    List<int> data,
    List<int> counter,
    int length,
  ) async {
    ArgumentError.checkNotNull(data, 'data');
    _checkArguments(counter, length);
    return await _bufferStream(encryptStream(
      Stream.value(data),
      counter,
      length,
    ));
  }

  @override
  Stream<Uint8List> encryptStream(
    Stream<List<int>> data,
    List<int> counter,
    int length,
  ) {
    ArgumentError.checkNotNull(data, 'data');
    _checkArguments(counter, length);
    return _aesCtrEncryptOrDecrypt(_key, true, data, counter, length);
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async =>
      _aesExportJwkKey(_key, jwkAlgSuffix: 'CTR');

  @override
  Future<Uint8List> exportRawKey() async => Uint8List.fromList(_key);
}

//---------------------- AES-CBC

Future<AesCbcSecretKey> aesCbc_importRawKey(List<int> keyData) async =>
    _AesCbcSecretKey(_aesImportRawKey(keyData));

Future<AesCbcSecretKey> aesCbc_importJsonWebKey(
  Map<String, dynamic> jwk,
) async =>
    _AesCbcSecretKey(_aesImportJwkKey(
      jwk,
      expectedJwkAlgSuffix: 'CBC',
    ));

Future<AesCbcSecretKey> aesCbc_generateKey(int length) async =>
    _AesCbcSecretKey(_aesGenerateKey(length));

Stream<Uint8List> _aesCbcEncryptOrDecrypt(
  Uint8List key,
  bool encrypt,
  Stream<List<int>> source,
  List<int> iv,
) async* {
  final scope = _Scope();
  try {
    assert(key.length == 16 || key.length == 32);
    final cipher =
        key.length == 16 ? ssl.EVP_aes_128_cbc() : ssl.EVP_aes_256_cbc();
    final blockSize = ssl.AES_BLOCK_SIZE;

    final ivSize = ssl.EVP_CIPHER_iv_length(cipher);
    if (iv.length != ivSize) {
      throw ArgumentError.value(iv, 'iv', 'must be $ivSize bytes');
    }

    final ctx = scope.create(ssl.EVP_CIPHER_CTX_new, ssl.EVP_CIPHER_CTX_free);
    _checkOpIsOne(ssl.EVP_CipherInit_ex(
      ctx,
      cipher,
      ffi.nullptr,
      scope.dataAsPointer(key),
      scope.dataAsPointer(iv),
      encrypt ? 1 : 0,
    ));

    const bufSize = 4096;

    // Allocate an input buffer
    final inBuf = scope.allocate<ffi.Uint8>(count: bufSize);
    final inData = inBuf.asTypedList(bufSize);
    final inBytes = inBuf.cast<ssl.Bytes>();

    // Allocate an output buffer, notice that BoringSSL says output cannot be
    // more than input size + blockSize - 1
    final outBuf = scope.allocate<ffi.Uint8>(count: bufSize + blockSize);
    final outData = outBuf.asTypedList(bufSize + blockSize);
    final outBytes = outBuf.cast<ssl.Bytes>();

    // Allocate and output length integer
    final outLen = scope.allocate<ffi.Int32>();

    // Process data from source
    await for (final data in source) {
      int offset = 0;
      while (offset < data.length) {
        final N = math.min(data.length - offset, bufSize);
        inData.setAll(0, data.skip(offset).take(N));

        _checkOpIsOne(ssl.EVP_CipherUpdate(ctx, outBytes, outLen, inBytes, N));
        if (outLen.value > 0) {
          yield outData.sublist(0, outLen.value);
        }
        offset += N;
      }
    }
    // Output final block
    _checkOpIsOne(ssl.EVP_CipherFinal_ex(ctx, outBytes, outLen));
    if (outLen.value > 0) {
      yield outData.sublist(0, outLen.value);
    }
  } finally {
    scope.release();
  }
}

class _AesCbcSecretKey implements AesCbcSecretKey {
  final Uint8List _key;
  _AesCbcSecretKey(this._key);

  @override
  Future<Uint8List> decryptBytes(List<int> data, List<int> iv) async {
    ArgumentError.checkNotNull(data, 'data');
    ArgumentError.checkNotNull(iv, 'iv');
    return await _bufferStream(decryptStream(Stream.value(data), iv));
  }

  @override
  Stream<Uint8List> decryptStream(Stream<List<int>> data, List<int> iv) {
    ArgumentError.checkNotNull(data, 'data');
    ArgumentError.checkNotNull(iv, 'iv');
    return _aesCbcEncryptOrDecrypt(_key, false, data, iv);
  }

  @override
  Future<Uint8List> encryptBytes(List<int> data, List<int> iv) async {
    ArgumentError.checkNotNull(data, 'data');
    ArgumentError.checkNotNull(iv, 'iv');
    return await _bufferStream(encryptStream(Stream.value(data), iv));
  }

  @override
  Stream<Uint8List> encryptStream(Stream<List<int>> data, List<int> iv) {
    ArgumentError.checkNotNull(data, 'data');
    ArgumentError.checkNotNull(iv, 'iv');
    return _aesCbcEncryptOrDecrypt(_key, true, data, iv);
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async =>
      _aesExportJwkKey(_key, jwkAlgSuffix: 'CBC');

  @override
  Future<Uint8List> exportRawKey() async => Uint8List.fromList(_key);
}

//---------------------- AES-GCM

Future<AesGcmSecretKey> aesGcm_importRawKey(List<int> keyData) async =>
    _AesGcmSecretKey(_aesImportRawKey(keyData));

Future<AesGcmSecretKey> aesGcm_importJsonWebKey(
  Map<String, dynamic> jwk,
) async =>
    _AesGcmSecretKey(_aesImportJwkKey(
      jwk,
      expectedJwkAlgSuffix: 'GCM',
    ));

Future<AesGcmSecretKey> aesGcm_generateKey(int length) async =>
    _AesGcmSecretKey(_aesGenerateKey(length));

Future<Uint8List> _aesGcmEncryptDecrypt(
  List<int> key,
  List<int> data,
  List<int> iv,
  List<int> additionalData,
  int tagLength,
  bool encrypt,
) async {
  ArgumentError.checkNotNull(data, 'data');
  if (encrypt && data.length > (1 << 39) - 256) {
    // More than this is not allowed by Web crypto spec, we shall honor that.
    throw _OperationError('data may not be more than 2^39 - 256 bytes');
  }
  tagLength ??= 128;
  if (tagLength != 32 &&
      tagLength != 64 &&
      tagLength != 96 &&
      tagLength != 104 &&
      tagLength != 112 &&
      tagLength != 120 &&
      tagLength != 128) {
    throw _OperationError('tagLength must be 32, 64, 96, 104, 112, 120 or 128');
  }
  additionalData ??= [];

  final scope = _Scope();
  try {
    assert(key.length == 16 || key.length == 32);
    final aead = key.length == 16
        ? ssl.EVP_aead_aes_128_gcm()
        : ssl.EVP_aead_aes_256_gcm();

    final ctx = scope.create(
      () => ssl.EVP_AEAD_CTX_new(
        aead,
        scope.dataAsPointer(key),
        key.length,
        tagLength ~/ 8,
      ),
      ssl.EVP_AEAD_CTX_free,
    );

    if (encrypt) {
      final outLen = scope.allocate<ffi.IntPtr>();
      final maxOut = data.length + ssl.EVP_AEAD_max_overhead(aead);
      return _withOutPointer(maxOut, (ffi.Pointer<ssl.Bytes> out) {
        _checkOpIsOne(ssl.EVP_AEAD_CTX_seal(
          ctx,
          out.cast(),
          outLen,
          maxOut,
          scope.dataAsPointer(iv),
          iv.length,
          scope.dataAsPointer(data),
          data.length,
          scope.dataAsPointer(additionalData),
          additionalData.length,
        ));
      }).sublist(0, outLen.value);
    } else {
      final outLen = scope.allocate<ffi.IntPtr>();
      return _withOutPointer(data.length, (ffi.Pointer<ssl.Bytes> out) {
        _checkOpIsOne(ssl.EVP_AEAD_CTX_open(
          ctx,
          out.cast(),
          outLen,
          data.length,
          scope.dataAsPointer(iv),
          iv.length,
          scope.dataAsPointer(data),
          data.length,
          scope.dataAsPointer(additionalData),
          additionalData.length,
        ));
      }).sublist(0, outLen.value);
    }
  } finally {
    scope.release();
  }
}

class _AesGcmSecretKey implements AesGcmSecretKey {
  final Uint8List _key;
  _AesGcmSecretKey(this._key);

  @override
  Future<Uint8List> decryptBytes(
    List<int> data,
    List<int> iv, {
    List<int> additionalData,
    int tagLength = 128,
  }) async =>
      _aesGcmEncryptDecrypt(
        _key,
        data,
        iv,
        additionalData,
        tagLength,
        false,
      );

  @override
  Future<Uint8List> encryptBytes(
    List<int> data,
    List<int> iv, {
    List<int> additionalData,
    int tagLength = 128,
  }) async =>
      _aesGcmEncryptDecrypt(
        _key,
        data,
        iv,
        additionalData,
        tagLength,
        false,
      );

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async =>
      _aesExportJwkKey(_key, jwkAlgSuffix: 'GCM');

  @override
  Future<Uint8List> exportRawKey() async => Uint8List.fromList(_key);
}

//---------------------- ECDH

Future<EcdhPrivateKey> ecdhPrivateKey_importPkcs8Key(
  List<int> keyData,
  EllipticCurve curve,
) async =>
    _EcdhPrivateKey(_importPkcs8EcPrivateKey(keyData, curve));

Future<EcdhPrivateKey> ecdhPrivateKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  EllipticCurve curve,
) async =>
    _EcdhPrivateKey(_importJwkEcPrivateOrPublicKey(
      JsonWebKey.fromJson(jwk),
      curve,
      isPrivateKey: true,
      expectedUse: 'enc',
      expectedAlg: null, // ECDH has no validation of 'jwk.alg'
    ));

Future<KeyPair<EcdhPrivateKey, EcdhPublicKey>> ecdhPrivateKey_generateKey(
  EllipticCurve curve,
) async {
  final p = _generateEcKeyPair(curve);
  return _KeyPair(
    privateKey: _EcdhPrivateKey(p.privateKey),
    publicKey: _EcdhPublicKey(p.publicKey),
  );
}

Future<EcdhPublicKey> ecdhPublicKey_importRawKey(
  List<int> keyData,
  EllipticCurve curve,
) async =>
    _EcdhPublicKey(_importRawEcPublicKey(keyData, curve));

Future<EcdhPublicKey> ecdhPublicKey_importSpkiKey(
  List<int> keyData,
  EllipticCurve curve,
) async =>
    _EcdhPublicKey(_importSpkiEcPublicKey(keyData, curve));

Future<EcdhPublicKey> ecdhPublicKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  EllipticCurve curve,
) async =>
    _EcdhPublicKey(_importJwkEcPrivateOrPublicKey(
      JsonWebKey.fromJson(jwk),
      curve,
      isPrivateKey: false,
      expectedUse: 'enc',
      expectedAlg: null, // ECDH has no validation of 'jwk.alg'
    ));

class _EcdhPrivateKey with _Disposable implements EcdhPrivateKey {
  final ffi.Pointer<ssl.EVP_PKEY> _key;

  _EcdhPrivateKey(this._key);

  @override
  void _finalize() {
    ssl.EVP_PKEY_free(_key);
  }

  @override
  Future<Uint8List> deriveBits(EcdhPublicKey publicKey, int length) async {
    ArgumentError.checkNotNull(publicKey, 'publicKey');
    ArgumentError.checkNotNull(length, 'length');
    if (publicKey is! _EcdhPublicKey) {
      throw ArgumentError.value(
        publicKey,
        'publicKey',
        'custom implementations of EcdhPublicKey is not supported',
      );
    }
    if (length <= 0) {
      throw ArgumentError.value(length, 'length', 'must be positive');
    }
    final _publicKey = publicKey as _EcdhPublicKey;

    final pubEcKey = ssl.EVP_PKEY_get0_EC_KEY(_publicKey._key);
    final privEcKey = ssl.EVP_PKEY_get0_EC_KEY(_key);

    // Check that public/private key uses the same elliptic curve.
    if (ssl.EC_GROUP_get_curve_name(ssl.EC_KEY_get0_group(pubEcKey)) ==
        ssl.EC_GROUP_get_curve_name(ssl.EC_KEY_get0_group(privEcKey))) {
      // Note: web crypto will throw an InvalidAccessError here.
      throw ArgumentError.value(
        publicKey,
        'publicKey',
        'Public and private key for ECDH key derivation have the same '
            'elliptic curve',
      );
    }

    // Field size rounded up to 8 bits is the maximum number of bits we can
    // derive. The most significant bits will be zero in this case.
    final fieldSize = ssl.EC_GROUP_get_degree(ssl.EC_KEY_get0_group(privEcKey));
    final maxLength = 8 * (fieldSize / 8).ceil();
    if (length > maxLength) {
      throw _OperationError(
        'Length in ECDH key derivation is too large. '
        'Maximum allowed is $maxLength bits.',
      );
    }

    if (length == 0) {
      return Uint8List.fromList([]);
    }

    final lengthInBytes = (length / 8).ceil() * 8;
    final derived = _withOutPointer(lengthInBytes, (ffi.Pointer<ssl.Data> p) {
      final outLen = ssl.ECDH_compute_key(
        p,
        lengthInBytes,
        ssl.EC_KEY_get0_public_key(pubEcKey),
        privEcKey,
        ffi.nullptr,
      );
      _checkOp(outLen != -1, fallback: 'ECDH key derivation failed');
      _checkOp(
        outLen != lengthInBytes,
        message: 'internal error in ECDH key derivation',
      );
    });

    // Zero the most-significant bits, if length does not fit to bytes.
    final zeroBits = lengthInBytes * 8 - length;
    assert(zeroBits < 8);
    if (zeroBits > 0) {
      derived[0] &= 0xff << (8 - lengthInBytes);
    }

    return derived;
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async =>
      _exportJwkEcPrivateOrPublicKey(_key, isPrivateKey: true, jwkUse: 'enc');

  @override
  Future<Uint8List> exportPkcs8Key() async {
    return _withOutCBB((cbb) {
      _checkOp(ssl.EVP_marshal_private_key(cbb, _key) == 1);
    });
  }
}

class _EcdhPublicKey with _Disposable implements EcdhPublicKey {
  final ffi.Pointer<ssl.EVP_PKEY> _key;

  _EcdhPublicKey(this._key);

  @override
  void _finalize() {
    ssl.EVP_PKEY_free(_key);
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async =>
      _exportJwkEcPrivateOrPublicKey(_key, isPrivateKey: false, jwkUse: 'enc');

  @override
  Future<Uint8List> exportRawKey() async => _exportRawEcPublicKey(_key);

  @override
  Future<Uint8List> exportSpkiKey() async {
    return _withOutCBB((cbb) {
      _checkOp(ssl.EVP_marshal_public_key(cbb, _key) == 1);
    });
  }
}

//---------------------- HKDF

Future<HkdfSecretKey> hkdfSecretKey_importRawKey(List<int> keyData) async {
  ArgumentError.checkNotNull(keyData, 'keyData');
  return _HkdfSecretKey(Uint8List.fromList(keyData));
}

class _HkdfSecretKey implements HkdfSecretKey {
  final Uint8List _key;

  _HkdfSecretKey(this._key);

  @override
  Future<Uint8List> deriveBits(
    int length,
    Hash hash,
    List<int> salt,
    List<int> info,
  ) async {
    ArgumentError.checkNotNull(length, 'length');
    ArgumentError.checkNotNull(hash, 'hash');
    ArgumentError.checkNotNull(salt, 'salt');
    ArgumentError.checkNotNull(info, 'info');
    if (length < 0) {
      throw ArgumentError.value(length, 'length', 'must be positive integer');
    }
    final md = _Hash.fromHash(hash).MD;

    // Mirroring limitations in chromium:
    // https://chromium.googlesource.com/chromium/src/+/43d62c50b705f88c67b14539e91fd8fd017f70c4/components/webcrypto/algorithms/hkdf.cc#74
    if (length % 8 != 0) {
      throw _OperationError('The length for HKDF must be a multiple of 8 bits');
    }

    final lengthInBytes = length ~/ 8;

    final scope = _Scope();
    try {
      return _withOutPointer(lengthInBytes, (ffi.Pointer<ssl.Bytes> out) {
        final r = ssl.HKDF(
          out,
          lengthInBytes,
          md,
          scope.dataAsPointer(_key),
          _key.length,
          scope.dataAsPointer(salt),
          salt.length,
          scope.dataAsPointer(info),
          info.length,
        );
        if (r != 1) {
          final packed_error = ssl.ERR_peek_error();
          if (ssl.ERR_GET_LIB(packed_error) == ssl.ERR_LIB_HKDF &&
              ssl.ERR_GET_REASON(packed_error) == ssl.HKDF_R_OUTPUT_TOO_LARGE) {
            ssl.ERR_clear_error();
            throw _OperationError(
              'Length specified for HkdfSecretKey.deriveBits is too long',
            );
          }
          _checkOpIsOne(r, fallback: 'HKDF key derivation failed');
        }
      });
    } finally {
      scope.release();
    }
  }
}

//---------------------- PBKDF2

Future<Pbkdf2SecretKey> pbkdf2SecretKey_importRawKey(List<int> keyData) async {
  ArgumentError.checkNotNull(keyData, 'keyData');
  return _Pbkdf2SecretKey(Uint8List.fromList(keyData));
}

class _Pbkdf2SecretKey implements Pbkdf2SecretKey {
  final Uint8List _key;

  _Pbkdf2SecretKey(this._key);

  @override
  Future<Uint8List> deriveBits(
    int length,
    Hash hash,
    List<int> salt,
    int iterations,
  ) async {
    ArgumentError.checkNotNull(length, 'length');
    ArgumentError.checkNotNull(hash, 'hash');
    ArgumentError.checkNotNull(salt, 'salt');
    ArgumentError.checkNotNull(iterations, 'iterations');
    if (length < 0) {
      throw ArgumentError.value(length, 'length', 'must be positive integer');
    }
    final md = _Hash.fromHash(hash).MD;

    // Mirroring limitations in chromium:
    // https://chromium.googlesource.com/chromium/src/+/43d62c50b705f88c67b14539e91fd8fd017f70c4/components/webcrypto/algorithms/pbkdf2.cc#75
    if (length % 8 != 0) {
      throw _OperationError(
          'The length for PBKDF2 must be a multiple of 8 bits');
    }
    if (length == 0) {
      throw _OperationError(
          'A length of zero is not allowed Pbkdf2SecretKey.deriveBits');
    }
    if (iterations <= 0) {
      throw _OperationError(
          'Iterations <= 0 is not allowed for Pbkdf2SecretKey.deriveBits');
    }

    final lengthInBytes = length ~/ 8;

    final scope = _Scope();
    try {
      return _withOutPointer(lengthInBytes, (ffi.Pointer<ssl.Bytes> out) {
        _checkOpIsOne(ssl.PKCS5_PBKDF2_HMAC(
          scope.dataAsPointer(_key),
          _key.length,
          scope.dataAsPointer(salt),
          salt.length,
          iterations,
          md,
          lengthInBytes,
          out,
        ));
      });
    } finally {
      scope.release();
    }
  }
}
