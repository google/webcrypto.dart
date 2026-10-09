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

part of 'impl_ffi.dart';

/// Wrapper around [EVP_PKEY] backed by [NativeHandle] from `package:boring`.
extension type _EvpPKey._(NativeHandle<EVP_PKEY> _handle)
    implements NativeHandle<EVP_PKEY> {
  /// Allocate new [EVP_PKEY], attach finalizer and return the wrapped key.
  factory _EvpPKey() {
    final pkey = ssl.EVP_PKEY_new();
    _checkOp(pkey.address != 0, fallback: 'allocation failure');
    return _EvpPKey.wrap(pkey);
  }

  /// Wrap existing [EVP_PKEY] and attach `EVP_PKEY_free` native finalizer.
  _EvpPKey.wrap(ffi.Pointer<EVP_PKEY> pkey)
    : _handle = NativeHandle(pkey, ssl.addresses.EVP_PKEY_free);
}

// BoringSSL pushes errors onto a thread-local queue, and an isolate may resume
// on a different OS thread after an `await`. So consume errors right after the
// failing call, using _checkOp / _checkData or ERR_clear_error, rather than
// deferring it to a `finally` or BoringArena release that may run after an
// `await`. In tests, checkErrorStack fails if errors are left behind.

/// Throw [OperationError] if [condition] is `false`.
///
/// If [message] is given we use that, otherwise we use error from BoringSSL,
/// and if nothing is available there we use [fallback].
void _checkOp(bool condition, {String? message, String? fallback}) {
  if (!condition) {
    // Always extract the error to ensure we clear the error queue.
    final err = ssl.extractBoringSslError();
    message ??= err ?? fallback ?? 'unknown error';
    throw operationError(message);
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
    final err = ssl.extractBoringSslError();
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

extension on BoringArena {
  /// Call [create], return [T], and [release] when the arena is released.
  ///
  /// Throws [OperationError] if [create] returns `nullptr`.
  ffi.Pointer<T> create<T extends ffi.NativeType>(
    ffi.Pointer<T> Function() create,
    void Function(ffi.Pointer<T>) release,
  ) {
    final result = create();
    _checkOp(result.address != 0, fallback: 'allocation failed');
    return using(result, release);
  }

  ffi.Pointer<RSA> createRSA() => create(ssl.RSA_new, ssl.RSA_free);

  ffi.Pointer<BIGNUM> createBN() => create(ssl.BN_new, ssl.BN_free);

  ffi.Pointer<EVP_CIPHER_CTX> createEVP_CIPHER_CTX() =>
      create(ssl.EVP_CIPHER_CTX_new, ssl.EVP_CIPHER_CTX_free);
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
  final buffer = ssl.opensslAllocator<ffi.Uint8>(maxChunk);
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
    ssl.opensslAllocator.free(buffer);
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
  return BoringArena.run((scope) async {
    final ctx = scope.create(ssl.EVP_MD_CTX_new, ssl.EVP_MD_CTX_free);
    final pctx = config != null
        ? scope<ffi.Pointer<EVP_PKEY_CTX>>()
        : ffi.nullptr;
    _checkOpIsOne(
      ssl.EVP_DigestSignInit.invoke(ctx, pctx, md, ffi.nullptr, key),
    );
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
  return BoringArena.run((scope) async {
    // Create and initialize verification context
    final ctx = scope.create(ssl.EVP_MD_CTX_new, ssl.EVP_MD_CTX_free);
    final pctx = config != null
        ? scope<ffi.Pointer<EVP_PKEY_CTX>>()
        : ffi.nullptr;
    _checkOpIsOne(
      ssl.EVP_DigestVerifyInit.invoke(ctx, pctx, md, ffi.nullptr, key),
    );
    if (config != null) {
      config(pctx.value);
    }

    // Stream data to verification context
    await _streamToUpdate(data, ctx, ssl.EVP_DigestVerifyUpdate);

    // Verify signature
    final result = ssl.EVP_DigestVerifyFinal(
      ctx,
      scope.copyBytes(signature),
      signature.length,
    );
    if (result != 1) {
      // An invalid signature is a `false` result, not an error, so discard
      // what BoringSSL pushed, right here (see the comment above _checkOp).
      // Note: In this case we could probably assert that error is just
      //       signature related.
      ssl.ERR_clear_error();
    }
    return result == 1;
  });
}

/// Export private [key] as PKCS8.
Uint8List _exportPkcs8Key(_EvpPKey key) {
  return BoringArena.run((scope) {
    final cbb = scope.cbb();
    _checkOpIsOne(ssl.EVP_marshal_private_key.invoke(cbb, key));
    return cbb.toBytes();
  });
}

/// Export public [key] as SPKI.
Uint8List _exportSpkiKey(_EvpPKey key) {
  return BoringArena.run((scope) {
    final cbb = scope.cbb();
    _checkOpIsOne(ssl.EVP_marshal_public_key.invoke(cbb, key));
    return cbb.toBytes();
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
/// [RFC 7515 Section 2](https://www.rfc-editor.org/rfc/rfc7515#section-2)
///
/// Throw [FormatException] mentioning JWK property [prop] on failure.
Uint8List _jwkDecodeBase64UrlNoPadding(String unpadded, String prop) {
  try {
    final padded = unpadded.padRight(
      unpadded.length + ((4 - (unpadded.length % 4)) % 4),
      '=',
    );
    final decoded = base64Url.decode(padded);
    if (_jwkEncodeBase64UrlNoPadding(decoded) != unpadded) {
      throw const FormatException();
    }
    return decoded;
  } on FormatException {
    throw FormatException(
      'JWK property "$prop" is not url-safe base64 without padding',
      unpadded,
    );
  }
}

/// Encode url-safe base64 witout padding as specified in
/// [RFC 7515 Section 2](https://www.rfc-editor.org/rfc/rfc7515#section-2)
String _jwkEncodeBase64UrlNoPadding(List<int> data) {
  final padded = base64Url.encode(data);
  final i = padded.indexOf('=');
  if (i == -1) {
    return padded;
  }
  return padded.substring(0, i);
}
