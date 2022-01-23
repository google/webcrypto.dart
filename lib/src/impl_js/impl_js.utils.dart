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

part of impl_js;

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

/// Convert [publicExponent] to [Uint8List].
Uint8List _publicExponentAsBuffer(BigInt publicExponent) {
// Limit publicExponent allow-listed as in chromium:
  // https://chromium.googlesource.com/chromium/src/+/43d62c50b705f88c67b14539e91fd8fd017f70c4/components/webcrypto/algorithms/rsa.cc#286
  if (publicExponent != BigInt.from(3) &&
      publicExponent != BigInt.from(65537)) {
    throw UnsupportedError('publicExponent is not supported, try 3 or 65537');
  }
  return subtle.bigIntToUint8ListBigInteger(publicExponent);
}

/// Return the name of [curve] for use in Web Cryptography API.
String _curveToName(EllipticCurve curve) {
  switch (curve) {
    case EllipticCurve.p256:
      return 'P-256';
    case EllipticCurve.p384:
      return 'P-384';
    case EllipticCurve.p521:
      return 'P-521';
  }
  // This should never happen.
  // ignore: dead_code
  throw AssertionError('Unknown curve "$curve"');
}

Object _translateDomException(
  subtle.DomException e, {
  bool invalidAccessErrorIsArgumentError = false,
}) {
  var message = e.message;
  if (message == null || message.isEmpty) {
    message = 'browser threw "${e.toString()}"';
  }
  switch (e.name) {
    case 'SyntaxError':
      return ArgumentError(message);
    case 'QuotaExceededError':
      return ArgumentError(message);
    case 'NotSupportedError':
      return UnsupportedError(message);
    case 'DataError':
      return FormatException(message);
    case 'OperationError':
      return _OperationError(message);
    case 'InvalidAccessError':
      // InvalidAccessError occurs when the request operation is not valid for
      // the provided key. This is typically because:
      //  A) `CryptoKey.usages` is violated
      //     (exporting a key with extractable set to false),
      //  B) A key is used for the wrong operation
      //     (signing with AES key makes no sense),
      //  C) Doing ECDH key derivation using a key-pair from differnet curves.
      //
      // The (A) and (B) cases should be possible in this API. Strong typing
      // prevents (B). And this library always enables all permissible
      // operations when importing/generating keys.
      // Hence, unless we're handling errors from ECDH `deriveBits` we shall
      // consider 'InvalidAccessError' to be an internal error.
      if (invalidAccessErrorIsArgumentError) {
        throw ArgumentError(message);
      }
      // This should never happen, because it is only thrown when
      /// CryptoKey.usages isn't configured correctly. But this library allows
      /// all valid usages.
      return AssertionError(
        'Unexpected access error from web cryptography: $message',
      );
  }
  // Unknown exception, we cannot handle this case.
  return AssertionError('Unexpected exception from web cryptography'
      '"${e.name}", message: $message');
}

/// Handle instances of [subtle.DomException] specified in the
/// [Web Cryptograpy specification][1].
///
/// [1]: https://www.w3.org/TR/WebCryptoAPI/#SubtleCrypto-Exceptions
Future<T> _handleDomException<T>(
  Future<T> Function() fn, {
  bool invalidAccessErrorIsArgumentError = false,
}) async {
  try {
    return await fn();
  } on subtle.DomException catch (e) {
    throw _translateDomException(
      e,
      invalidAccessErrorIsArgumentError: invalidAccessErrorIsArgumentError,
    );
  }
}

final _usagesSignVerify = ['sign', 'verify'];
final _usagesSign = ['sign'];
final _usagesVerify = ['verify'];
final _usagesEncryptDecrypt = ['encrypt', 'decrypt'];
final _usagesDecrypt = ['decrypt'];
final _usagesEncrypt = ['encrypt'];
final _usagesDeriveBits = ['deriveBits'];

/// Adapt `crypto.subtle.importKey` to Dart types for JWK.
Future<subtle.CryptoKey> _importJsonWebKey(
  Map<String, dynamic> jwk,
  subtle.Algorithm algorithm,
  List<String> usages,
  String expectedType,
) {
  return _handleDomException(() async {
    final jwkObj = subtle.JsonWebKey.fromJson(jwk);
    // TODO: Validate expected 'use' the way we have it in the FFI implementation

    // Remove 'key_ops' and 'ext' as this library doesn't configuring
    // _usages_ and _extractable_.
    // Notice that we also strip 'key_ops' and 'ext' in [_exportJsonWebKey].
    jwkObj.key_ops = null;
    jwkObj.ext = null;
    final k = await subtle.importJsonWebKey(
      'jwk',
      jwkObj,
      algorithm,
      true, // extractable, keys should always be extractable.
      usages,
    );
    if (k.type != expectedType) {
      throw ArgumentError.value(jwk, 'jwk', 'must be a "$expectedType" key');
    }
    return k;
  });
}

/// Adapt `crypto.subtle.importKey` to Dart types.
Future<subtle.CryptoKey> _importKey(
  String format,
  List<int> keyData,
  subtle.Algorithm algorithm,
  List<String> usages,
  String expectedType, {
  bool extractable = true, // most keys should always be extractable
}) {
  return _handleDomException(() async {
    final k = await subtle.importKey(
      format,
      Uint8List.fromList(keyData),
      algorithm,
      extractable,
      usages,
    );
    if (k.type != expectedType) {
      throw ArgumentError.value(
          keyData, 'keyData', 'must be a "$expectedType" key');
    }
    return k;
  });
}

/// Adapt `crypto.subtle.sign` to Dart types.
Future<Uint8List> _sign(
  subtle.Algorithm algorithm,
  subtle.CryptoKey key,
  List<int> data,
) {
  ArgumentError.checkNotNull(data, 'data');

  return _handleDomException(() async {
    final result = await subtle.sign(
      algorithm,
      key,
      Uint8List.fromList(data),
    );
    return result.asUint8List();
  });
}

/// Adapt `crypto.subtle.verify` to Dart types.
Future<bool> _verify(
  subtle.Algorithm algorithm,
  subtle.CryptoKey key,
  List<int> signature,
  List<int> data,
) {
  ArgumentError.checkNotNull(signature, 'signature');
  ArgumentError.checkNotNull(data, 'data');

  return _handleDomException(() async {
    return await subtle.verify(
      algorithm,
      key,
      Uint8List.fromList(signature),
      Uint8List.fromList(data),
    );
  });
}

/// Adapt `crypto.subtle.encrypt` to Dart types.
Future<Uint8List> _encrypt(
  subtle.Algorithm algorithm,
  subtle.CryptoKey key,
  List<int> data,
) {
  ArgumentError.checkNotNull(data, 'data');

  return _handleDomException(() async {
    final result = await subtle.encrypt(
      algorithm,
      key,
      Uint8List.fromList(data),
    );
    return result.asUint8List();
  });
}

/// Adapt `crypto.subtle.decrypt` to Dart types.
Future<Uint8List> _decrypt(
  subtle.Algorithm algorithm,
  subtle.CryptoKey key,
  List<int> data,
) {
  ArgumentError.checkNotNull(data, 'data');

  return _handleDomException(() async {
    final result = await subtle.decrypt(
      algorithm,
      key,
      Uint8List.fromList(data),
    );
    return result.asUint8List();
  });
}

/// Adapt `crypto.subtle.deriveBits` to Dart types.
Future<Uint8List> _deriveBits(
  subtle.Algorithm algorithm,
  subtle.CryptoKey key,
  int length, {
  bool invalidAccessErrorIsArgumentError = false,
}) {
  ArgumentError.checkNotNull(length, 'length');

  return _handleDomException(() async {
    final result = await subtle.deriveBits(
      algorithm,
      key,
      length,
    );
    return result.asUint8List();
  }, invalidAccessErrorIsArgumentError: invalidAccessErrorIsArgumentError);
}

/// Adapt `crypto.subtle.export` to Dart types.
Future<Uint8List> _exportKey(
  String format,
  subtle.CryptoKey key,
) {
  ArgumentError.checkNotNull(format, 'format');

  return _handleDomException(() async {
    final result = await subtle.exportKey(format, key);
    return result.asUint8List();
  });
}

/// Adapt `crypto.subtle.export` to Dart types.
Future<Map<String, Object>> _exportJsonWebKey(
  subtle.CryptoKey key,
  // TODO: Add expected 'use' the way we have it in the FFI implementation
) {
  return _handleDomException(() async {
    final jwk = await subtle.exportJsonWebKey(
      'jwk',
      key,
    );
    // Remove 'key_ops' and 'ext' as this library doesn't allow configuration of
    // _usages_ or _extractable_.
    // Notice, that we also strip these in [_importJsonWebKey].
    jwk.key_ops = null;
    jwk.ext = null;
    return jwk.toJson();
  });
}

/// Adapt `crypto.subtle.generateKey` to Dart types.
Future<subtle.CryptoKey> _generateKey(
  subtle.Algorithm algorithm,
  List<String> usages,
  String expectedType,
) {
  return _handleDomException(() async {
    final k = await subtle.generateKey(
      algorithm,
      true, // extractable, keys should always be extractable.
      usages,
    );
    assert(k.type == expectedType, 'expected a "$expectedType" key');
    return k;
  });
}

/// Adapt `crypto.subtle.generateKey` to Dart types.
Future<subtle.CryptoKeyPair> _generateKeyPair(
  subtle.Algorithm algorithm,
  List<String> usages,
) {
  return _handleDomException(() async {
    final pair = await subtle.generateKeyPair(
      algorithm,
      true, // extractable, keys should always be extractable.
      usages,
    );
    // Sanity check the generated keys
    assert(pair.privateKey.type == 'private');
    assert(pair.publicKey.type == 'public');
    return pair;
  });
}
