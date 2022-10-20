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

// ignore_for_file: non_constant_identifier_names

part of impl_ffi;

/// Wrapper around [EVP_PKEY] which attaches finalizer and ensure that the
/// [ffi.Finalizable] is kept in scope while the [EVP_PKEY] is used.
class _EvpPKey implements ffi.Finalizable {
  /// We don't really have an estimate of how much space the EVP_PKEY structure
  /// takes up, but if we make it some non-trivial size then hopefully the GC
  /// will prioritize freeing them.
  static const _externalSizeEstimate = 4096;

  static final _finalizer =
      ffi.NativeFinalizer(ssl.addresses.EVP_PKEY_free.cast());

  final ffi.Pointer<EVP_PKEY> _pkey;

  /// Allocate new [EVP_PKEY], attach finalizer and return the wrapped key.
  factory _EvpPKey() {
    final pkey = ssl.EVP_PKEY_new();
    _checkOp(pkey.address != 0, fallback: 'allocation failure');
    return _EvpPKey.wrap(pkey);
  }

  /// Wrap existing [EVP_PKEY], this will attach a finalizer.
  ///
  /// After this, the wrapped key may only be used within a callback passed to
  /// [use]. Otherwise, the garbage collect may be calling the finalizer while
  /// the key is in use.
  _EvpPKey.wrap(this._pkey) {
    _finalizer.attach(this, _pkey.cast(), externalSize: _externalSizeEstimate);
  }

  /// Use the wrapped [EVP_PKEY] in callback [fn].
  ///
  /// Note. [fn] is not allowed to return a [Future].
  T use<T>(T Function(ffi.Pointer<EVP_PKEY> pkey) fn) => fn(_pkey);
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
    final out = _sslAlloc<ffi.Char>(N);
    try {
      ssl.ERR_error_string_n(err, out, N);
      final data = out.cast<ffi.Uint8>().asTypedList(N);
      // Take everything until '\0'
      return utf8.decode(data.takeWhile((i) => i != 0).toList());
    } finally {
      _sslAlloc.free(out);
    }
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
  ffi.Pointer<T> allocate<T extends ffi.NativeType>(
    int byteCount, {
    int? alignment,
  }) {
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
  ffi.Pointer<T> allocate<T extends ffi.NativeType>(
    int byteCount, {
    int? alignment,
  }) {
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
  ///
  /// Instead of calling this directly, prefer to use:
  ///  * [_Scope.async],
  ///  * [_Scope.sync], or,
  ///  * [_Scope.stream].
  void _release() {
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

  /// Run [fn] with a [_Scope] that is released when the [Future] returned
  /// from [fn] is completed.
  static Future<T> async<T>(FutureOr<T> Function(_Scope scope) fn) async {
    assert(T is! Future, 'avoid nested async blocks');
    final scope = _Scope();
    try {
      return await fn(scope);
    } finally {
      scope._release();
    }
  }

  /// Run [fn] with a [_Scope] that is released when the [Stream] returned
  /// from [fn] is completed.
  static Stream<T> stream<T>(Stream<T> Function(_Scope scope) fn) async* {
    final scope = _Scope();
    try {
      yield* fn(scope);
    } finally {
      scope._release();
    }
  }

  /// Run [fn] with a [_Scope] that is released when [fn] returns.
  ///
  /// Use [async] if [fn] is an async function that returns a [Future].
  static T sync<T>(T Function(_Scope scope) fn) {
    assert(T is! Future, 'avoid nested async blocks');
    final scope = _Scope();
    try {
      return fn(scope);
    } finally {
      scope._release();
    }
  }
}

extension on _Scope {
  ffi.Pointer<RSA> createRSA() => create(ssl.RSA_new, ssl.RSA_free);

  ffi.Pointer<BIGNUM> createBN() => create(ssl.BN_new, ssl.BN_free);

  ffi.Pointer<EVP_CIPHER_CTX> createEVP_CIPHER_CTX() =>
      create(ssl.EVP_CIPHER_CTX_new, ssl.EVP_CIPHER_CTX_free);

  ffi.Pointer<CBS> createCBS(List<int> data) {
    final cbs = this<CBS>();
    ssl.CBS_init(cbs, dataAsPointer(data), data.length);
    return cbs;
  }

  ffi.Pointer<CBB> createCBB([int sizeHint = 4096]) {
    final cbb = this<CBB>();
    ssl.CBB_zero(cbb);
    _checkOp(ssl.CBB_init(cbb, sizeHint) == 1, fallback: 'allocation failure');
    defer(() => ssl.CBB_cleanup(cbb));
    return cbb;
  }
}

extension on ffi.Pointer<CBB> {
  /// Copy contents of this [CBB] to a [Uint8List].
  Uint8List copy() {
    _checkOp(ssl.CBB_flush(this) == 1);
    final bytes = ssl.CBB_data(this);
    final len = ssl.CBB_len(this);
    return Uint8List.fromList(bytes.asTypedList(len));
  }
}

extension on ffi.Pointer<ffi.Uint8> {
  /// Copy [length] bytes from pointer to [Uint8List] owned by Dart.
  Uint8List copy(int length) => Uint8List.fromList(asTypedList(length));
}

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

/// Sign [data] using [key] and [md], with optional configuration specified
/// using [config].
Future<Uint8List> _signStream(
  _EvpPKey key,
  ffi.Pointer<EVP_MD> md,
  Stream<List<int>> data, {
  void Function(ffi.Pointer<EVP_PKEY_CTX> ctx)? config,
}) {
  return _Scope.async((scope) async {
    final ctx = scope.create(ssl.EVP_MD_CTX_new, ssl.EVP_MD_CTX_free);
    final pctx =
        config != null ? scope<ffi.Pointer<EVP_PKEY_CTX>>() : ffi.nullptr;
    _checkOpIsOne(ssl.EVP_DigestSignInit.invoke(
      ctx,
      pctx,
      md,
      ffi.nullptr,
      key,
    ));
    if (config != null) {
      config(pctx.value);
    }

    // Stream data into the signature context
    await _streamToUpdate(data, ctx, ssl.EVP_DigestSignUpdate);

    // Get length of the output signature
    final len = scope<ffi.Size>();
    len.value = 0;
    _checkOpIsOne(ssl.EVP_DigestSignFinal(ctx, ffi.nullptr, len));
    // Get the output signature
    final out = scope<ffi.Uint8>(len.value);
    _checkOpIsOne(ssl.EVP_DigestSignFinal(ctx, out, len));
    return out.copy(len.value);
  });
}

/// Verify [signature] matches [data] given [key] and [md], with optional
/// configuration specified using [config].
Future<bool> _verifyStream(
  _EvpPKey key,
  ffi.Pointer<EVP_MD> md,
  List<int> signature,
  Stream<List<int>> data, {
  void Function(ffi.Pointer<EVP_PKEY_CTX> ctx)? config,
}) {
  return _Scope.async((scope) async {
    // Create and initialize verification context
    final ctx = scope.create(ssl.EVP_MD_CTX_new, ssl.EVP_MD_CTX_free);
    final pctx =
        config != null ? scope<ffi.Pointer<EVP_PKEY_CTX>>() : ffi.nullptr;
    _checkOpIsOne(ssl.EVP_DigestVerifyInit.invoke(
      ctx,
      pctx,
      md,
      ffi.nullptr,
      key,
    ));
    if (config != null) {
      config(pctx.value);
    }

    // Stream data to verification context
    await _streamToUpdate(data, ctx, ssl.EVP_DigestVerifyUpdate);

    // Verify signature
    final result = ssl.EVP_DigestVerifyFinal(
      ctx,
      scope.dataAsPointer(signature),
      signature.length,
    );
    if (result != 1) {
      // TODO: We should always clear errors, when returning from any
      //       function that uses BoringSSL.
      // Note: In this case we could probably assert that error is just
      //       signature related.
      ssl.ERR_clear_error();
    }
    return result == 1;
  });
}

/// Export private [key] as PKCS8.
Uint8List _exportPkcs8Key(_EvpPKey key) {
  return _Scope.sync((scope) {
    final cbb = scope.createCBB();
    _checkOpIsOne(ssl.EVP_marshal_private_key.invoke(cbb, key));
    return cbb.copy();
  });
}

/// Export public [key] as SPKI.
Uint8List _exportSpkiKey(_EvpPKey key) {
  return _Scope.sync((scope) {
    final cbb = scope.createCBB();
    _checkOpIsOne(ssl.EVP_marshal_public_key.invoke(cbb, key));
    return cbb.copy();
  });
}

/// Convert [Stream<List<int>>] to [Uint8List].
Future<Uint8List> _bufferStream(Stream<List<int>> data) async {
  final b = BytesBuilder();
  await for (final chunk in data) {
    b.add(chunk);
  }
  return b.takeBytes();
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
