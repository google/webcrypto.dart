// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

part of impl_ffi;

/// Function that can't be inlined to be used for preventing [obj] from being
/// garbage collected.
@pragma('vm:never-inline')
Object _finalizerReachabilityFence(Object obj) {
  return obj;
}

/// Wrapper around [EVP_PKEY] which attaches finalizer and ensures that the
/// [_finalizerReachabilityFence] is used after usage.
///
/// The [_finalizerReachabilityFence] ensures that the [_EvpPKey] is not garbage
/// collected while the wrapped key is use. Thus, we can be sure the finalizer
/// won't be called while the wrapped key is in use.
class _EvpPKey {
  final ffi.Pointer<EVP_PKEY> _pkey;

  /// Allocate new [EVP_PKEY], attach finalizer and return the wrapped key.
  factory _EvpPKey() {
    final _pkey = ssl.EVP_PKEY_new();
    _checkOp(_pkey.address != 0, fallback: 'allocation failure');
    return _EvpPKey.wrap(_pkey);
  }

  /// Wrap existing [EVP_PKEY], this will attach a finalizer.
  ///
  /// After this, the wrapped key may only be used within a callback passed to
  /// [use]. Otherwise, the garbage collect may be calling the finalizer while
  /// the key is in use.
  _EvpPKey.wrap(this._pkey) {
    final ret = dl.webcrypto_dart_dl_attach_finalizer(
      this,
      _pkey.cast(),
      ssl.addresses.EVP_PKEY_free.cast(),
      // We don't really have an estimate of how much space the EVP_PKEY structure
      // takes up, but if we make it some non-trivial size then hopefully the GC
      // will prioritize freeing them.
      4096,
    );
    if (ret != 1) {
      throw AssertionError('package:webcrypto failed to attached finalizer');
    }
  }

  /// Use the wrapped [EVP_PKEY] in callback [fn].
  ///
  /// Note. [fn] is not allowed to return a [Future].
  T use<T>(T Function(ffi.Pointer<EVP_PKEY> pkey) fn) {
    try {
      return fn(_pkey);
    } finally {
      _finalizerReachabilityFence(this);
    }
  }
}

/// Extension of native function that takes a [EVP_PKEY], making it easy to call
/// using a wrapped [_EvpPKey].
extension<T> on T Function(ffi.Pointer<EVP_PKEY>) {
  /// Invoke this function with unwrapped [key].
  T invoke(_EvpPKey key) => key.use((pkey) => this(pkey));
}

/// Extension of native function that takes a [EVP_PKEY], making it easy to call
/// using a wrapped [_EvpPKey].
extension<T, A1> on T Function(ffi.Pointer<EVP_PKEY>, A1) {
  /// Invoke this function with unwrapped [key].
  T invoke(_EvpPKey key, A1 arg1) => key.use((pkey) => this(pkey, arg1));
}

/// Extension of native function that takes a [EVP_PKEY], making it easy to call
/// using a wrapped [_EvpPKey].
extension<T, A1> on T Function(A1, ffi.Pointer<EVP_PKEY>) {
  /// Invoke this function with unwrapped [key].
  T invoke(A1 arg1, _EvpPKey key) => key.use((pkey) => this(arg1, pkey));
}

/// Extension of native function that takes a [EVP_PKEY], making it easy to call
/// using a wrapped [_EvpPKey].
extension<T, A1, A2, A3, A4> on T Function(
    A1, A2, A3, A4, ffi.Pointer<EVP_PKEY>) {
  /// Invoke this function with unwrapped [key].
  T invoke(
    A1 arg1,
    A2 arg2,
    A3 arg3,
    A4 arg4,
    _EvpPKey key,
  ) =>
      key.use((pkey) => this(
            arg1,
            arg2,
            arg3,
            arg4,
            pkey,
          ));
}

/// Throw [OperationError] if [condition] is `false`.
///
/// If [message] is given we use that, otherwise we use error from BoringSSL,
/// and if nothing is available there we use [fallback].
void _checkOp(bool condition, {String? message, String? fallback}) {
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
void _checkOpIsOne(int retval, {String? message, String? fallback}) =>
    _checkOp(retval == 1, message: message, fallback: fallback);

/// Throw [FormatException] if [condition] is `false`.
///
/// If [message] is given we use that, otherwise we use error from BoringSSL,
/// and if nothing is available there we use [fallback].
void _checkData(bool condition, {String? message, String? fallback}) {
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
void _checkDataIsOne(int retval, {String? message, String? fallback}) =>
    _checkData(retval == 1, message: message, fallback: fallback);

/// Extract latest error on this thread as [String] and clear the error queue
/// for this thread.
///
/// Returns `null` if there is no error.
String? _extractError() {
  try {
    // Get the error.
    final err = ssl.ERR_get_error();
    if (err == 0) {
      return null;
    }
    const N = 4096; // Max error message size
    final data = _withOutPointer(N, (ffi.Pointer<ffi.Int8> p) {
      ssl.ERR_error_string_n(err, p, N);
    });
    // Take everything until '\0'
    return utf8.decode(data.takeWhile((i) => i != 0).toList());
  } finally {
    // Always clear error queue, so we continue
    ssl.ERR_clear_error();
  }
}

class _SslAllocator implements Allocator {
  const _SslAllocator();

  /// Allocate [byteCount] bytes.
  ///
  /// Must be de-allocated with [free].
  @override
  ffi.Pointer<T> allocate<T extends ffi.NativeType>(int byteCount,
      {int? alignment}) {
    // TODO: Find out why OPENSSL_malloc doesn't work on Dart on Linux.
    //       This presumably has to do with dlopen(), WEAK symbols and the fact
    //       that the `dart` executable that ships in the Dart-SDK for Linux is
    //       a _release build_, not a _product build_, so more symbols might be
    //       visible. In anycase using ffi.allocate / ffi.free works fine on
    //       the `dart` executable with the Dart-SDK for Linux.
    //       Please note, that this does not work with the Flutter or the `dart`
    //       binary that ships with the Flutter SDK.
    final p = ssl.OPENSSL_malloc(byteCount);
    _checkOp(p.address != 0, fallback: 'allocation failure');
    return p.cast<T>();
  }

  /// Release memory allocated with [allocate].
  @override
  void free(ffi.Pointer pointer) {
    ssl.OPENSSL_free(pointer.cast());
  }
}

const _sslAlloc = _SslAllocator();

class _ScopeEntry {
  final Object? handle;
  final void Function() fn;

  _ScopeEntry(this.handle, this.fn);
}

// Utility for tracking and releasing memory.
class _Scope implements Allocator {
  final List<_ScopeEntry> _deferred = [];

  /// Defer [fn] to end of this scope.
  void defer(void Function() fn, [Object? handle]) =>
      _deferred.add(_ScopeEntry(handle, fn));

  /// Allocate an [ffi.Pointer<T>] in this scope.
  @override
  ffi.Pointer<T> allocate<T extends ffi.NativeType>(int byteCount,
      {int? alignment}) {
    final p = _sslAlloc.allocate<T>(byteCount);
    defer(() => _sslAlloc.free(p), p);
    return p;
  }

  /// Allocate and copy [data] to an [ffi.Pointer<T>] in this scope.
  ffi.Pointer<T> dataAsPointer<T extends ffi.NativeType>(List<int> data) {
    final p = _sslAlloc<ffi.Uint8>(data.length);
    p.asTypedList(data.length).setAll(0, data);
    final result = p.cast<T>();
    defer(() => _sslAlloc.free(p), result);
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

  @override
  void free(ffi.Pointer pointer) {
    // Does nothing, use `release` instead.
    // Not throwing, so that this can actually be used as an Allocator.
  }
}

/// Invoke [fn] with [p], and release [p] when [fn] returns.
R _withAllocation<T extends ffi.NativeType, R>(
  ffi.Pointer<T> p,
  R Function(ffi.Pointer<T>) fn,
) {
  assert(R is! Future, 'avoid async blocks');
  try {
    return fn(p);
  } finally {
    _sslAlloc.free(p);
  }
}

/// Invoke [fn] with [p],and release [p] when future returned by [fn]
/// completes.
Future<R> _withAllocationAsync<T extends ffi.NativeType, R>(
  ffi.Pointer<T> p,
  FutureOr<R> Function(ffi.Pointer<T>) fn,
) async {
  assert(R is! Future, 'avoid nested async blocks');
  try {
    return await fn(p);
  } finally {
    _sslAlloc.free(p);
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
  return _withAllocation(_sslAlloc<ffi.Uint8>(size),
      (ffi.Pointer<ffi.Uint8> p) {
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
  return _withAllocation(_sslAlloc<ffi.Uint8>(data.length),
      (ffi.Pointer<ffi.Uint8> p) {
    p.asTypedList(data.length).setAll(0, data);
    return fn(p.cast<T>());
  });
}

/// Invoke [fn] with an [ffi.Pointer<EVP_MD_CTX>] that is free'd when
/// [fn] returns.
Future<R> _withEVP_MD_CTX<R>(
  FutureOr<R> Function(ffi.Pointer<EVP_MD_CTX>) fn,
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
  FutureOr<R> Function(ffi.Pointer<ffi.Pointer<EVP_PKEY_CTX>> pctx) fn,
) =>
    _withAllocationAsync(_sslAlloc<ffi.Pointer<EVP_PKEY_CTX>>(), fn);

/// Stream bytes from [source] to [update] with [ctx], useful for streaming
/// algorithms. Notice that chunk size from [data] may be altered.
Future<void> _streamToUpdate<T, S extends ffi.NativeType>(
  Stream<List<int>> source,
  T ctx,
  int Function(T, ffi.Pointer<S>, int) update,
) async {
  const maxChunk = 4096;
  final buffer = _sslAlloc<ffi.Uint8>(maxChunk);
  try {
    final ptr = buffer.cast<S>();
    final bytes = buffer.asTypedList(maxChunk);
    await for (final data in source) {
      var offset = 0;
      while (offset < data.length) {
        final N = math.min(data.length - offset, maxChunk);
        bytes.setAll(0, data.skip(offset).take(N));
        _checkOp(update(ctx, ptr, N) == 1);
        offset += N;
      }
    }
  } finally {
    _sslAlloc.free(buffer);
  }
}

/// Invoke [fn] with [data] loaded into a [ffi.Pointer<ssl.CBS>].
///
/// Both the [ssl.CBS] and the [ssl.Bytes] pointer allocated will be released
/// when [fn] returns.
R _withDataAsCBS<R>(List<int> data, R Function(ffi.Pointer<CBS>) fn) {
  return _withDataAsPointer(data, (ffi.Pointer<ffi.Uint8> p) {
    return _withAllocation(_sslAlloc<CBS>(), (ffi.Pointer<CBS> cbs) {
      ssl.CBS_init(cbs, p, data.length);
      return fn(cbs);
    });
  });
}

/// Call [fn] with an initialized [ffi.Pointer<ssl.CBB>] and return the result
/// as [Uint8List].
Uint8List _withOutCBB(void Function(ffi.Pointer<CBB>) fn) {
  return _withAllocation(_sslAlloc<CBB>(), (ffi.Pointer<CBB> cbb) {
    ssl.CBB_zero(cbb);
    try {
      _checkOp(ssl.CBB_init(cbb, 4096) == 1, fallback: 'allocation failure');
      fn(cbb);
      _checkOp(ssl.CBB_flush(cbb) == 1);
      final bytes = ssl.CBB_data(cbb);
      final len = ssl.CBB_len(cbb);
      return Uint8List.fromList(bytes.asTypedList(len));
    } finally {
      ssl.CBB_cleanup(cbb);
    }
  });
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
