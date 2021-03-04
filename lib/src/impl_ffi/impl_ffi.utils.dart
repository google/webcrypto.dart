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

/// Attach a finalizer for [key], this means that [ssl.EVP_PKEY_free] will
/// automatically be called with [key] is garbage collected by Dart.
///
/// This takes ownership of [key], and the caller **may not** call
/// [ssl.EVP_PKEY_free].
///
/// Callers should be ware that the Dart GC may collect [key] as soon as it
/// deems the object to not be in use anymore. This can happy at any point when
/// the VM (optimizer) determines that no code-path passing [key] to an FFI
/// function can be called again. For this reason, users should take extra care
/// to make sure that all accesses to [key] takes an extra reference.
void _attachFinalizerEVP_PKEY(ffi.Pointer<EVP_PKEY> key) {
  final ret = ssl.webcrypto_dart_dl_attach_finalizer(
    key,
    key.cast(),
    EVP_PKEY_free_.cast(),
    // We don't really have an estimate of how much space the EVP_PKEY structure
    // takes up, but if we make it some non-trivial size then hopefully the GC
    // will prioritize freeing them.
    4096,
  );
  if (ret != 1) {
    throw AssertionError('package:webcrypto failed to attached finalizer');
  }
}

/// Create an [ssl.EVP_PKEY] with finalizer attached.
///
/// See [_attachFinalizerEVP_PKEY] for notes on how the finalizer works.
ffi.Pointer<EVP_PKEY> _createEVP_PKEYwithFinalizer() {
  final key = ssl.EVP_PKEY_new();
  _checkOp(key.address != 0, fallback: 'allocation failure');
  _attachFinalizerEVP_PKEY(key);
  return key;
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

/// Allocate [count] (default 1) size of [T] bytes.
///
/// Must be de-allocated with [_free].
ffi.Pointer<T> _malloc<T extends ffi.NativeType>({int count = 1}) {
  // TODO: Find out why OPENSSL_malloc doesn't work on Dart on Linux.
  //       This presumably has to do with dlopen(), WEAK symbols and the fact
  //       that the `dart` executable that ships in the Dart-SDK for Linux is
  //       a _release build_, not a _product build_, so more symbols might be
  //       visible. In anycase using ffi.allocate / ffi.free works fine on
  //       the `dart` executable with the Dart-SDK for Linux.
  //       Please note, that this does not work with the Flutter or the `dart`
  //       binary that ships with the Flutter SDK.
  // return ffi.allocate<T>(count: count);
  // TODO(dacoharkes): Migrate this to an SslAllocator implements Allocator.
  final p = ssl.OPENSSL_malloc(count * ffi.sizeOf<T>());
  _checkOp(p.address != 0, fallback: 'allocation failure');
  return p.cast<T>();
}

/// Release memory allocated with [_malloc]
void _free<T extends ffi.NativeType>(ffi.Pointer<T> p) {
  // If using the ffi.allocate<T>(count: count) hack from [_malloc] we must also
  // use ffi.free(p) here. See [_malloc] for details.
  // ffi.free(p);
  ssl.OPENSSL_free(p.cast());
}

class _ScopeEntry {
  final Object? handle;
  final void Function() fn;

  _ScopeEntry(this.handle, this.fn);
}

// Utility for tracking and releasing memory.
class _Scope {
  final List<_ScopeEntry> _deferred = [];

  /// Defer [fn] to end of this scope.
  void defer(void Function() fn, [Object? handle]) =>
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
      var offset = 0;
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
R _withDataAsCBS<R>(List<int> data, R Function(ffi.Pointer<CBS>) fn) {
  return _withDataAsPointer(data, (ffi.Pointer<ffi.Uint8> p) {
    return _withAllocation(1, (ffi.Pointer<CBS> cbs) {
      ssl.CBS_init(cbs, p, data.length);
      return fn(cbs);
    });
  });
}

/// Call [fn] with an initialized [ffi.Pointer<ssl.CBB>] and return the result
/// as [Uint8List].
Uint8List _withOutCBB(void Function(ffi.Pointer<CBB>) fn) {
  return _withAllocation(1, (ffi.Pointer<CBB> cbb) {
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
