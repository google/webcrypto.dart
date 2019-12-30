import 'dart:async';
import 'dart:typed_data';

import '../webcrypto.dart';
import 'crypto_subtle.dart' as subtle;

//---------------------- Wrappers

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
// Limit publicExponent whitelist as in chromium:
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
  throw AssertionError('Unknown curve "$curve"');
}

Object _translateDomException(subtle.DomException e) {
  switch (e.name) {
    case 'SyntaxError':
      return ArgumentError(e.message);
    case 'QuotaExceededError':
      return ArgumentError(e.message);
    case 'NotSupportedError':
      return UnsupportedError(e.message);
    case 'DataError':
      return FormatException(e.message);
    case 'OperationError':
      return _OperationError(e.message);
    case 'InvalidAccessError':
      // This should never happen, because it is only thrown when
      /// CryptoKey.usages isn't configured correctly. But this library allows
      /// all valid usages.
      return AssertionError(
        'Unexpected access error from web cryptography: ${e.message}',
      );
  }
  // Unknown exception, we cannot handle this case.
  return AssertionError('Unexpected exception from web cryptography'
      '"${e.name}", message: ${e.message}');
}

/// Handle instances of [subtle.DomException] specified in the
/// [Web Cryptograpy specification][1].
///
/// [1]: https://www.w3.org/TR/WebCryptoAPI/#SubtleCrypto-Exceptions
Future<T> _handleDomException<T>(Future<T> Function() fn) async {
  try {
    return await fn();
  } on subtle.DomException catch (e) {
    throw _translateDomException(e);
  }
}

final _usagesSignVerify = ['sign', 'verify'];
final _usagesSign = ['sign'];
final _usagesVerify = ['verify'];
final _usagesEncryptDecrypt = ['encrypt', 'decrypt'];
final _usagesDecrypt = ['decrypt'];
final _usagesDeriveBits = ['deriveBits'];

/// Adapt `crypto.subtle.importKey` to Dart types for JWK.
Future<subtle.CryptoKey> _importJsonWebKey(
  Map<String, Object> jwk,
  subtle.Algorithm algorithm,
  List<String> usages,
  String expectedType,
) {
  return _handleDomException(() async {
    // TODO: Consider reading the JWK and stripping away any usage restrictions
    //       Also verify that usage restrictions allows for usages listed.
    //       Reject keys that don't allow for usages we request.
    final k = await subtle.promiseAsFuture(subtle.importJsonWebKey(
      'jwk',
      subtle.JsonWebKey.fromJson(jwk),
      algorithm,
      true, // extractable, keys should always be extractable.
      usages,
    ));
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
  String expectedType,
) {
  return _handleDomException(() async {
    final k = await subtle.promiseAsFuture(subtle.importKey(
      format,
      Uint8List.fromList(keyData),
      algorithm,
      true, // extractable, keys should always be extractable.
      usages,
    ));
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
    final result = await subtle.promiseAsFuture(subtle.sign(
      algorithm,
      key,
      await Uint8List.fromList(data),
    ));
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
    return await subtle.promiseAsFuture(subtle.verify(
      algorithm,
      key,
      Uint8List.fromList(signature),
      Uint8List.fromList(data),
    ));
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
    final result = await subtle.promiseAsFuture(subtle.encrypt(
      algorithm,
      key,
      await Uint8List.fromList(data),
    ));
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
    final result = await subtle.promiseAsFuture(subtle.decrypt(
      algorithm,
      key,
      await Uint8List.fromList(data),
    ));
    return result.asUint8List();
  });
}

/// Adapt `crypto.subtle.deriveBits` to Dart types.
Future<Uint8List> _deriveBits(
  subtle.Algorithm algorithm,
  subtle.CryptoKey key,
  int length,
) {
  ArgumentError.checkNotNull(length, 'length');

  return _handleDomException(() async {
    final result = await subtle.promiseAsFuture(subtle.deriveBits(
      algorithm,
      key,
      length,
    ));
    return result.asUint8List();
  });
}

/// Adapt `crypto.subtle.export` to Dart types.
Future<Uint8List> _exportKey(
  String format,
  subtle.CryptoKey key,
) {
  ArgumentError.checkNotNull(format, 'format');

  return _handleDomException(() async {
    final result = await subtle.promiseAsFuture(subtle.exportKey(format, key));
    return result.asUint8List();
  });
}

/// Adapt `crypto.subtle.export` to Dart types.
Future<Map<String, Object>> _exportJsonWebKey(
  subtle.CryptoKey key,
) {
  return _handleDomException(() async {
    final result = await subtle.promiseAsFuture(subtle.exportJsonWebKey(
      'jwk',
      key,
    ));
    return subtle.JsonWebKey.toJson(result);
  });
}

/// Adapt `crypto.subtle.generateKey` to Dart types.
Future<subtle.CryptoKey> _generateKey(
  subtle.Algorithm algorithm,
  List<String> usages,
  String expectedType,
) {
  return _handleDomException(() async {
    final k = await subtle.promiseAsFuture(subtle.generateKey(
      algorithm,
      true, // extractable, keys should always be extractable.
      usages,
    ));
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
    final pair = await subtle.promiseAsFuture(subtle.generateKeyPair(
      algorithm,
      true, // extractable, keys should always be extractable.
      usages,
    ));
    // Sanity check the generated keys
    assert(pair.privateKey.type == 'private');
    assert(pair.publicKey.type == 'public');
    return pair;
  });
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

//---------------------- Random Bytes

void fillRandomBytes(TypedData destination) {
  try {
    subtle.getRandomValues(destination);
  } on subtle.DomException catch (e) {
    throw _translateDomException(e);
  }
}

//---------------------- Hash Algorithms

class _Hash implements Hash {
  final String _algorithm;
  const _Hash(this._algorithm);

  @override
  Future<Uint8List> digestBytes(List<int> data) async {
    return await _handleDomException(() async {
      final result = await subtle.promiseAsFuture(subtle.digest(
        _algorithm,
        Uint8List.fromList(data),
      ));
      return result.asUint8List();
    });
  }

  @override
  Future<Uint8List> digestStream(Stream<List<int>> data) async {
    return await digestBytes(await _bufferStream(data));
  }
}

const Hash sha1 = _Hash('SHA-1');
const Hash sha256 = _Hash('SHA-256');
const Hash sha384 = _Hash('SHA-384');
const Hash sha512 = _Hash('SHA-512');

/// Get the algorithm from [hash] or throw an [ArgumentError].
String _getHashAlgorithm(Hash hash) {
  if (hash is _Hash) {
    return hash._algorithm;
  }
  throw ArgumentError.value(
    hash,
    'hash',
    'Only built-in hash functions is allowed',
  );
}

//---------------------- HMAC

final _hmacAlgorithm = subtle.Algorithm(name: 'HMAC');

Future<HmacSecretKey> hmacSecretKey_importRawKey(
  List<int> keyData,
  Hash hash, {
  int length,
}) async {
  return _HmacSecretKey(await _importKey(
    'raw',
    keyData,
    length == null
        ? subtle.Algorithm(
            name: 'HMAC',
            hash: _getHashAlgorithm(hash),
          )
        : subtle.Algorithm(
            name: 'HMAC',
            hash: _getHashAlgorithm(hash),
            length: length,
          ),
    _usagesSignVerify,
    'secret',
  ));
}

Future<HmacSecretKey> hmacSecretKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  Hash hash, {
  int length,
}) async {
  return _HmacSecretKey(await _importJsonWebKey(
    jwk,
    length == null
        ? subtle.Algorithm(
            name: 'HMAC',
            hash: _getHashAlgorithm(hash),
          )
        : subtle.Algorithm(
            name: 'HMAC',
            hash: _getHashAlgorithm(hash),
            length: length,
          ),
    _usagesSignVerify,
    'secret',
  ));
}

Future<HmacSecretKey> hmacSecretKey_generateKey(Hash hash, {int length}) async {
  return _HmacSecretKey(await _generateKey(
    length == null
        ? subtle.Algorithm(
            name: 'HMAC',
            hash: _getHashAlgorithm(hash),
          )
        : subtle.Algorithm(
            name: 'HMAC',
            hash: _getHashAlgorithm(hash),
            length: length,
          ),
    _usagesSignVerify,
    'secret',
  ));
}

class _HmacSecretKey implements HmacSecretKey {
  final subtle.CryptoKey _key;
  _HmacSecretKey(this._key);

  @override
  Future<Uint8List> signBytes(List<int> data) async {
    return await _sign(_hmacAlgorithm, _key, data);
  }

  @override
  Future<Uint8List> signStream(Stream<List<int>> data) async {
    return await signBytes(await _bufferStream(data));
  }

  @override
  Future<bool> verifyBytes(List<int> signature, List<int> data) async {
    return await _verify(_hmacAlgorithm, _key, signature, data);
  }

  @override
  Future<bool> verifyStream(List<int> signature, Stream<List<int>> data) async {
    return await verifyBytes(signature, await _bufferStream(data));
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async {
    return await _exportJsonWebKey(_key);
  }

  @override
  Future<Uint8List> exportRawKey() async {
    return await _exportKey('raw', _key);
  }
}

//---------------------- RSASSA_PKCS1_v1_5

final _rsassaPkcs1V15Algorithm = subtle.Algorithm(name: 'RSASSA-PKCS1-v1_5');

Future<RsassaPkcs1V15PrivateKey> rsassaPkcs1V15PrivateKey_importPkcs8Key(
  List<int> keyData,
  Hash hash,
) async {
  return _RsassaPkcs1V15PrivateKey(await _importKey(
    'pkcs8',
    keyData,
    subtle.Algorithm(
      name: _rsassaPkcs1V15Algorithm.name,
      hash: _getHashAlgorithm(hash),
    ),
    _usagesSign,
    'private',
  ));
}

Future<RsassaPkcs1V15PrivateKey> rsassaPkcs1V15PrivateKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  Hash hash,
) async {
  return _RsassaPkcs1V15PrivateKey(await _importJsonWebKey(
    jwk,
    subtle.Algorithm(
      name: _rsassaPkcs1V15Algorithm.name,
      hash: _getHashAlgorithm(hash),
    ),
    _usagesSign,
    'private',
  ));
}

Future<KeyPair<RsassaPkcs1V15PrivateKey, RsassaPkcs1V15PublicKey>>
    rsassaPkcs1V15PrivateKey_generateKey(
  int modulusLength,
  BigInt publicExponent,
  Hash hash,
) async {
  final pair = await _generateKeyPair(
    subtle.Algorithm(
      name: _rsassaPkcs1V15Algorithm.name,
      hash: _getHashAlgorithm(hash),
      publicExponent: _publicExponentAsBuffer(publicExponent),
      modulusLength: modulusLength,
    ),
    _usagesSignVerify,
  );
  return _KeyPair(
    privateKey: _RsassaPkcs1V15PrivateKey(pair.privateKey),
    publicKey: _RsassaPkcs1V15PublicKey(pair.publicKey),
  );
}

Future<RsassaPkcs1V15PublicKey> rsassaPkcs1V15PublicKey_importSpkiKey(
  List<int> keyData,
  Hash hash,
) async {
  return _RsassaPkcs1V15PublicKey(await _importKey(
    'spki',
    keyData,
    subtle.Algorithm(
      name: _rsassaPkcs1V15Algorithm.name,
      hash: _getHashAlgorithm(hash),
    ),
    _usagesVerify,
    'public',
  ));
}

Future<RsassaPkcs1V15PublicKey> rsassaPkcs1V15PublicKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  Hash hash,
) async {
  return _RsassaPkcs1V15PublicKey(await _importJsonWebKey(
    jwk,
    subtle.Algorithm(
      name: _rsassaPkcs1V15Algorithm.name,
      hash: _getHashAlgorithm(hash),
    ),
    _usagesVerify,
    'public',
  ));
}

class _RsassaPkcs1V15PrivateKey implements RsassaPkcs1V15PrivateKey {
  final subtle.CryptoKey _key;
  _RsassaPkcs1V15PrivateKey(this._key);

  @override
  Future<Uint8List> signBytes(List<int> data) async {
    return await _sign(_rsassaPkcs1V15Algorithm, _key, data);
  }

  @override
  Future<Uint8List> signStream(Stream<List<int>> data) async {
    return await signBytes(await _bufferStream(data));
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async {
    return await _exportJsonWebKey(_key);
  }

  @override
  Future<Uint8List> exportPkcs8Key() async {
    return await _exportKey('pkcs8', _key);
  }
}

class _RsassaPkcs1V15PublicKey implements RsassaPkcs1V15PublicKey {
  final subtle.CryptoKey _key;
  _RsassaPkcs1V15PublicKey(this._key);

  @override
  Future<bool> verifyBytes(List<int> signature, List<int> data) async {
    return await _verify(_rsassaPkcs1V15Algorithm, _key, signature, data);
  }

  @override
  Future<bool> verifyStream(List<int> signature, Stream<List<int>> data) async {
    return await verifyBytes(signature, await _bufferStream(data));
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async {
    return await _exportJsonWebKey(_key);
  }

  @override
  Future<Uint8List> exportSpkiKey() async {
    return await _exportKey('spki', _key);
  }
}

//---------------------- RSA-PSS

final _rsaPssAlgorithmName = 'RSA-PSS';

Future<RsaPssPrivateKey> rsaPssPrivateKey_importPkcs8Key(
  List<int> keyData,
  Hash hash,
) async {
  return _RsaPssPrivateKey(await _importKey(
    'pkcs8',
    keyData,
    subtle.Algorithm(name: _rsaPssAlgorithmName, hash: _getHashAlgorithm(hash)),
    _usagesSign,
    'private',
  ));
}

Future<RsaPssPrivateKey> rsaPssPrivateKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  Hash hash,
) async {
  return _RsaPssPrivateKey(await _importJsonWebKey(
    jwk,
    subtle.Algorithm(name: _rsaPssAlgorithmName, hash: _getHashAlgorithm(hash)),
    _usagesSign,
    'private',
  ));
}

Future<KeyPair<RsaPssPrivateKey, RsaPssPublicKey>> rsaPssPrivateKey_generateKey(
  int modulusLength,
  BigInt publicExponent,
  Hash hash,
) async {
  final pair = await _generateKeyPair(
    subtle.Algorithm(
      name: _rsaPssAlgorithmName,
      hash: _getHashAlgorithm(hash),
      publicExponent: _publicExponentAsBuffer(publicExponent),
      modulusLength: modulusLength,
    ),
    _usagesSignVerify,
  );
  return _KeyPair(
    privateKey: _RsaPssPrivateKey(pair.privateKey),
    publicKey: _RsaPssPublicKey(pair.publicKey),
  );
}

Future<RsaPssPublicKey> rsaPssPublicKey_importSpkiKey(
  List<int> keyData,
  Hash hash,
) async {
  return _RsaPssPublicKey(await _importKey(
    'spki',
    keyData,
    subtle.Algorithm(name: _rsaPssAlgorithmName, hash: _getHashAlgorithm(hash)),
    _usagesVerify,
    'public',
  ));
}

Future<RsaPssPublicKey> rsaPssPublicKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  Hash hash,
) async {
  return _RsaPssPublicKey(await _importJsonWebKey(
    jwk,
    subtle.Algorithm(name: _rsaPssAlgorithmName, hash: _getHashAlgorithm(hash)),
    _usagesVerify,
    'public',
  ));
}

class _RsaPssPrivateKey implements RsaPssPrivateKey {
  final subtle.CryptoKey _key;
  _RsaPssPrivateKey(this._key);

  @override
  Future<Uint8List> signBytes(List<int> data, int saltLength) async {
    return await _sign(
      subtle.Algorithm(name: _rsaPssAlgorithmName, saltLength: saltLength),
      _key,
      data,
    );
  }

  @override
  Future<Uint8List> signStream(Stream<List<int>> data, int saltLength) async {
    return await signBytes(await _bufferStream(data), saltLength);
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async {
    return await _exportJsonWebKey(_key);
  }

  @override
  Future<Uint8List> exportPkcs8Key() async {
    return await _exportKey('pkcs8', _key);
  }
}

class _RsaPssPublicKey implements RsaPssPublicKey {
  final subtle.CryptoKey _key;
  _RsaPssPublicKey(this._key);

  @override
  Future<bool> verifyBytes(
    List<int> signature,
    List<int> data,
    int saltLength,
  ) async {
    return await _verify(
      subtle.Algorithm(name: _rsaPssAlgorithmName, saltLength: saltLength),
      _key,
      signature,
      data,
    );
  }

  @override
  Future<bool> verifyStream(
    List<int> signature,
    Stream<List<int>> data,
    int saltLength,
  ) async {
    return await verifyBytes(signature, await _bufferStream(data), saltLength);
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async {
    return await _exportJsonWebKey(_key);
  }

  @override
  Future<Uint8List> exportSpkiKey() async {
    return await _exportKey('spki', _key);
  }
}

//---------------------- ECDSA

final _ecdsaAlgorithmName = 'ECDSA';

Future<EcdsaPrivateKey> ecdsaPrivateKey_importPkcs8Key(
  List<int> keyData,
  EllipticCurve curve,
) async {
  return _EcdsaPrivateKey(await _importKey(
    'pkcs8',
    keyData,
    subtle.Algorithm(
      name: _ecdsaAlgorithmName,
      namedCurve: _curveToName(curve),
    ),
    _usagesSign,
    'private',
  ));
}

Future<EcdsaPrivateKey> ecdsaPrivateKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  EllipticCurve curve,
) async {
  return _EcdsaPrivateKey(await _importJsonWebKey(
    jwk,
    subtle.Algorithm(
      name: _ecdsaAlgorithmName,
      namedCurve: _curveToName(curve),
    ),
    _usagesSign,
    'private',
  ));
}

Future<KeyPair<EcdsaPrivateKey, EcdsaPublicKey>> ecdsaPrivateKey_generateKey(
  EllipticCurve curve,
) async {
  final pair = await _generateKeyPair(
    subtle.Algorithm(
      name: _ecdsaAlgorithmName,
      namedCurve: _curveToName(curve),
    ),
    _usagesSignVerify,
  );
  return _KeyPair(
    privateKey: _EcdsaPrivateKey(pair.privateKey),
    publicKey: _EcdsaPublicKey(pair.publicKey),
  );
}

Future<EcdsaPublicKey> ecdsaPublicKey_importRawKey(
  List<int> keyData,
  EllipticCurve curve,
) async {
  return _EcdsaPublicKey(await _importKey(
    'raw',
    keyData,
    subtle.Algorithm(
      name: _ecdsaAlgorithmName,
      namedCurve: _curveToName(curve),
    ),
    _usagesVerify,
    'public',
  ));
}

Future<EcdsaPublicKey> ecdsaPublicKey_importSpkiKey(
  List<int> keyData,
  EllipticCurve curve,
) async {
  return _EcdsaPublicKey(await _importKey(
    'spki',
    keyData,
    subtle.Algorithm(
      name: _ecdsaAlgorithmName,
      namedCurve: _curveToName(curve),
    ),
    _usagesVerify,
    'public',
  ));
}

Future<EcdsaPublicKey> ecdsaPublicKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  EllipticCurve curve,
) async {
  return _EcdsaPublicKey(await _importJsonWebKey(
    jwk,
    subtle.Algorithm(
      name: _ecdsaAlgorithmName,
      namedCurve: _curveToName(curve),
    ),
    _usagesVerify,
    'public',
  ));
}

class _EcdsaPrivateKey implements EcdsaPrivateKey {
  final subtle.CryptoKey _key;
  _EcdsaPrivateKey(this._key);

  @override
  Future<Uint8List> signBytes(List<int> data, Hash hash) async {
    return await _sign(
      subtle.Algorithm(
        name: _ecdsaAlgorithmName,
        hash: _getHashAlgorithm(hash),
      ),
      _key,
      data,
    );
  }

  @override
  Future<Uint8List> signStream(Stream<List<int>> data, Hash hash) async {
    return await signBytes(await _bufferStream(data), hash);
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async {
    return await _exportJsonWebKey(_key);
  }

  @override
  Future<Uint8List> exportPkcs8Key() async {
    return await _exportKey('pkcs8', _key);
  }
}

class _EcdsaPublicKey implements EcdsaPublicKey {
  final subtle.CryptoKey _key;
  _EcdsaPublicKey(this._key);

  @override
  Future<bool> verifyBytes(
      List<int> signature, List<int> data, Hash hash) async {
    return await _verify(
      subtle.Algorithm(
        name: _ecdsaAlgorithmName,
        hash: _getHashAlgorithm(hash),
      ),
      _key,
      signature,
      data,
    );
  }

  @override
  Future<bool> verifyStream(
    List<int> signature,
    Stream<List<int>> data,
    Hash hash,
  ) async {
    return await verifyBytes(signature, await _bufferStream(data), hash);
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async {
    return await _exportJsonWebKey(_key);
  }

  @override
  Future<Uint8List> exportRawKey() async {
    return await _exportKey('raw', _key);
  }

  @override
  Future<Uint8List> exportSpkiKey() async {
    return await _exportKey('spki', _key);
  }
}

//---------------------- RSA-OAEP

final _rsaOaepAlgorithmName = 'RSA-OAEP';

Future<RsaOaepPrivateKey> rsaOaepPrivateKey_importPkcs8Key(
  List<int> keyData,
  Hash hash,
) async {
  return _RsaOaepPrivateKey(await _importKey(
    'pkcs8',
    keyData,
    subtle.Algorithm(
      name: _rsaOaepAlgorithmName,
      hash: _getHashAlgorithm(hash),
    ),
    _usagesDecrypt,
    'private',
  ));
}

Future<RsaOaepPrivateKey> rsaOaepPrivateKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  Hash hash,
) async {
  return _RsaOaepPrivateKey(await _importJsonWebKey(
    jwk,
    subtle.Algorithm(
      name: _rsaOaepAlgorithmName,
      hash: _getHashAlgorithm(hash),
    ),
    _usagesDecrypt,
    'private',
  ));
}

Future<KeyPair<RsaOaepPrivateKey, RsaPssPublicKey>>
    rsaOaepPrivateKey_generateKey(
  int modulusLength,
  BigInt publicExponent,
  Hash hash,
) async {
  final pair = await _generateKeyPair(
    subtle.Algorithm(
      name: _rsaOaepAlgorithmName,
      hash: _getHashAlgorithm(hash),
    ),
    _usagesEncryptDecrypt,
  );
  return _KeyPair(
    privateKey: _RsaOaepPrivateKey(pair.privateKey),
    publicKey: _RsaPssPublicKey(pair.publicKey),
  );
}

Future<RsaOaepPublicKey> rsaOaepPublicKey_importSpkiKey(
  List<int> keyData,
  Hash hash,
) async {
  return _RsaOaepPublicKey(await _importKey(
    'spki',
    keyData,
    subtle.Algorithm(
      name: _rsaOaepAlgorithmName,
      hash: _getHashAlgorithm(hash),
    ),
    _usagesDecrypt,
    'public',
  ));
}

Future<RsaOaepPublicKey> rsaOaepPublicKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  Hash hash,
) async {
  return _RsaOaepPublicKey(await _importJsonWebKey(
    jwk,
    subtle.Algorithm(
      name: _rsaOaepAlgorithmName,
      hash: _getHashAlgorithm(hash),
    ),
    _usagesDecrypt,
    'public',
  ));
}

class _RsaOaepPrivateKey implements RsaOaepPrivateKey {
  final subtle.CryptoKey _key;
  _RsaOaepPrivateKey(this._key);

  @override
  Future<Uint8List> decryptBytes(List<int> data, {List<int> label}) async {
    return _decrypt(
      label == null
          ? subtle.Algorithm(name: _rsaOaepAlgorithmName)
          : subtle.Algorithm(
              name: _rsaOaepAlgorithmName,
              label: Uint8List.fromList(label),
            ),
      _key,
      data,
    );
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async {
    return await _exportJsonWebKey(_key);
  }

  @override
  Future<Uint8List> exportPkcs8Key() async {
    return await _exportKey('pkcs8', _key);
  }
}

class _RsaOaepPublicKey implements RsaOaepPublicKey {
  final subtle.CryptoKey _key;
  _RsaOaepPublicKey(this._key);

  @override
  Future<Uint8List> encryptBytes(List<int> data, {List<int> label}) async {
    return _encrypt(
      label == null
          ? subtle.Algorithm(name: _rsaOaepAlgorithmName)
          : subtle.Algorithm(
              name: _rsaOaepAlgorithmName,
              label: Uint8List.fromList(label),
            ),
      _key,
      data,
    );
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async {
    return await _exportJsonWebKey(_key);
  }

  @override
  Future<Uint8List> exportSpkiKey() async {
    return await _exportKey('spki', _key);
  }
}

//---------------------- AES-CTR

final _aesCtrAlgorithm = subtle.Algorithm(name: 'AES-CTR');

Future<AesCtrSecretKey> aesCtr_importRawKey(List<int> keyData) async {
  return _AesCtrSecretKey(await _importKey(
    'raw',
    keyData,
    _aesCtrAlgorithm,
    _usagesEncryptDecrypt,
    'secret',
  ));
}

Future<AesCtrSecretKey> aesCtr_importJsonWebKey(
  Map<String, dynamic> jwk,
) async {
  return _AesCtrSecretKey(await _importJsonWebKey(
    jwk,
    _aesCtrAlgorithm,
    _usagesEncryptDecrypt,
    'secret',
  ));
}

Future<AesCtrSecretKey> aesCtr_generateKey(int length) async {
  return _AesCtrSecretKey(await _generateKey(
    subtle.Algorithm(
      name: _aesCtrAlgorithm.name,
      length: length,
    ),
    _usagesEncryptDecrypt,
    'secret',
  ));
}

class _AesCtrSecretKey implements AesCtrSecretKey {
  final subtle.CryptoKey _key;
  _AesCtrSecretKey(this._key);

  @override
  Future<Uint8List> decryptBytes(
    List<int> data,
    List<int> counter,
    int length,
  ) async {
    ArgumentError.checkNotNull(counter, 'counter');
    ArgumentError.checkNotNull(length, 'length');
    return await _decrypt(
      subtle.Algorithm(
        name: _aesCtrAlgorithm.name,
        counter: Uint8List.fromList(counter),
        length: length,
      ),
      _key,
      data,
    );
  }

  @override
  Stream<Uint8List> decryptStream(
    Stream<List<int>> data,
    List<int> counter,
    int length,
  ) async* {
    yield await decryptBytes(await _bufferStream(data), counter, length);
  }

  @override
  Future<Uint8List> encryptBytes(
    List<int> data,
    List<int> counter,
    int length,
  ) async {
    ArgumentError.checkNotNull(counter, 'counter');
    ArgumentError.checkNotNull(length, 'length');
    return await _encrypt(
      subtle.Algorithm(
        name: _aesCtrAlgorithm.name,
        counter: Uint8List.fromList(counter),
        length: length,
      ),
      _key,
      data,
    );
  }

  @override
  Stream<Uint8List> encryptStream(
    Stream<List<int>> data,
    List<int> counter,
    int length,
  ) async* {
    yield await encryptBytes(await _bufferStream(data), counter, length);
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async {
    return await _exportJsonWebKey(_key);
  }

  @override
  Future<Uint8List> exportRawKey() async {
    return await _exportKey('raw', _key);
  }
}

//---------------------- AES-CBC

final _aesCbcAlgorithm = subtle.Algorithm(name: 'AES-CBC');

Future<AesCbcSecretKey> aesCbc_importRawKey(List<int> keyData) async {
  return _AesCbcSecretKey(await _importKey(
    'raw',
    keyData,
    _aesCbcAlgorithm,
    _usagesEncryptDecrypt,
    'secret',
  ));
}

Future<AesCbcSecretKey> aesCbc_importJsonWebKey(
  Map<String, dynamic> jwk,
) async {
  return _AesCbcSecretKey(await _importJsonWebKey(
    jwk,
    _aesCbcAlgorithm,
    _usagesEncryptDecrypt,
    'secret',
  ));
}

Future<AesCbcSecretKey> aesCbc_generateKey(int length) async {
  return _AesCbcSecretKey(await _generateKey(
    subtle.Algorithm(
      name: _aesCbcAlgorithm.name,
      length: length,
    ),
    _usagesEncryptDecrypt,
    'secret',
  ));
}

class _AesCbcSecretKey implements AesCbcSecretKey {
  final subtle.CryptoKey _key;
  _AesCbcSecretKey(this._key);

  @override
  Future<Uint8List> decryptBytes(List<int> data, List<int> iv) async {
    ArgumentError.checkNotNull(iv, 'iv');
    return await _decrypt(
      subtle.Algorithm(
        name: _aesCbcAlgorithm.name,
        iv: Uint8List.fromList(iv),
      ),
      _key,
      data,
    );
  }

  @override
  Stream<Uint8List> decryptStream(Stream<List<int>> data, List<int> iv) async* {
    yield await decryptBytes(await _bufferStream(data), iv);
  }

  @override
  Future<Uint8List> encryptBytes(List<int> data, List<int> iv) async {
    ArgumentError.checkNotNull(iv, 'iv');
    // TODO: Validate all input arguments, iv must be 16 bytes
    return await _encrypt(
      subtle.Algorithm(
        name: _aesCbcAlgorithm.name,
        iv: Uint8List.fromList(iv),
      ),
      _key,
      data,
    );
  }

  @override
  Stream<Uint8List> encryptStream(Stream<List<int>> data, List<int> iv) async* {
    yield await encryptBytes(await _bufferStream(data), iv);
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async {
    return await _exportJsonWebKey(_key);
  }

  @override
  Future<Uint8List> exportRawKey() async {
    return await _exportKey('raw', _key);
  }
}

//---------------------- AES-GCM

final _aesGcmAlgorithm = subtle.Algorithm(name: 'AES-GCM');

Future<AesGcmSecretKey> aesGcm_importRawKey(List<int> keyData) async {
  return _AesGcmSecretKey(await _importKey(
    'raw',
    keyData,
    _aesGcmAlgorithm,
    _usagesEncryptDecrypt,
    'secret',
  ));
}

Future<AesGcmSecretKey> aesGcm_importJsonWebKey(
  Map<String, dynamic> jwk,
) async {
  return _AesGcmSecretKey(await _importJsonWebKey(
    jwk,
    _aesGcmAlgorithm,
    _usagesEncryptDecrypt,
    'secret',
  ));
}

Future<AesGcmSecretKey> aesGcm_generateKey(int length) async {
  return _AesGcmSecretKey(await _generateKey(
    subtle.Algorithm(
      name: _aesGcmAlgorithm.name,
      length: length,
    ),
    _usagesEncryptDecrypt,
    'secret',
  ));
}

class _AesGcmSecretKey implements AesGcmSecretKey {
  final subtle.CryptoKey _key;
  _AesGcmSecretKey(this._key);

  @override
  Future<Uint8List> decryptBytes(
    List<int> data,
    List<int> iv, {
    List<int> additionalData,
    int tagLength = 128,
  }) async {
    ArgumentError.checkNotNull(iv, 'iv');
    ArgumentError.checkNotNull(tagLength, 'tagLength');
    return await _decrypt(
      additionalData == null
          ? subtle.Algorithm(
              name: _aesGcmAlgorithm.name,
              iv: Uint8List.fromList(iv),
              tagLength: tagLength,
            )
          : subtle.Algorithm(
              name: _aesGcmAlgorithm.name,
              iv: Uint8List.fromList(iv),
              additionalData: Uint8List.fromList(additionalData),
              tagLength: tagLength,
            ),
      _key,
      data,
    );
  }

  @override
  Stream<Uint8List> decryptStream(
    Stream<List<int>> data,
    List<int> iv, {
    List<int> additionalData,
    int tagLength = 128,
  }) async* {
    yield await decryptBytes(await _bufferStream(data), iv);
  }

  @override
  Future<Uint8List> encryptBytes(
    List<int> data,
    List<int> iv, {
    List<int> additionalData,
    int tagLength = 128,
  }) async {
    ArgumentError.checkNotNull(iv, 'iv');
    ArgumentError.checkNotNull(tagLength, 'tagLength');
    return await _encrypt(
      additionalData == null
          ? subtle.Algorithm(
              name: _aesGcmAlgorithm.name,
              iv: Uint8List.fromList(iv),
              tagLength: tagLength,
            )
          : subtle.Algorithm(
              name: _aesGcmAlgorithm.name,
              iv: Uint8List.fromList(iv),
              additionalData: Uint8List.fromList(additionalData),
              tagLength: tagLength,
            ),
      _key,
      data,
    );
  }

  @override
  Stream<Uint8List> encryptStream(
    Stream<List<int>> data,
    List<int> iv, {
    List<int> additionalData,
    int tagLength = 128,
  }) async* {
    yield await encryptBytes(await _bufferStream(data), iv);
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async {
    return await _exportJsonWebKey(_key);
  }

  @override
  Future<Uint8List> exportRawKey() async {
    return await _exportKey('raw', _key);
  }
}

//---------------------- ECDH

final _ecdhAlgorithmName = 'ECDH';

Future<EcdhPrivateKey> ecdhPrivateKey_importPkcs8Key(
  List<int> keyData,
  EllipticCurve curve,
) async {
  return _EcdhPrivateKey(await _importKey(
    'pkcs8',
    keyData,
    subtle.Algorithm(
      name: _ecdhAlgorithmName,
      namedCurve: _curveToName(curve),
    ),
    _usagesDeriveBits,
    'private',
  ));
}

Future<EcdhPrivateKey> ecdhPrivateKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  EllipticCurve curve,
) async {
  return _EcdhPrivateKey(await _importJsonWebKey(
    jwk,
    subtle.Algorithm(
      name: _ecdhAlgorithmName,
      namedCurve: _curveToName(curve),
    ),
    _usagesDeriveBits,
    'private',
  ));
}

Future<KeyPair<EcdhPrivateKey, EcdhPublicKey>> ecdhPrivateKey_generateKey(
  EllipticCurve curve,
) async {
  final pair = await _generateKeyPair(
    subtle.Algorithm(
      name: _ecdhAlgorithmName,
      namedCurve: _curveToName(curve),
    ),
    _usagesDeriveBits,
  );
  return _KeyPair(
    privateKey: _EcdhPrivateKey(pair.privateKey),
    publicKey: _EcdhPublicKey(pair.publicKey),
  );
}

Future<EcdhPublicKey> ecdhPublicKey_importRawKey(
  List<int> keyData,
  EllipticCurve curve,
) async {
  return _EcdhPublicKey(await _importKey(
    'raw',
    keyData,
    subtle.Algorithm(
      name: _ecdhAlgorithmName,
      namedCurve: _curveToName(curve),
    ),
    _usagesDeriveBits,
    'public',
  ));
}

Future<EcdhPublicKey> ecdhPublicKey_importSpkiKey(
  List<int> keyData,
  EllipticCurve curve,
) async {
  return _EcdhPublicKey(await _importKey(
    'spki',
    keyData,
    subtle.Algorithm(
      name: _ecdhAlgorithmName,
      namedCurve: _curveToName(curve),
    ),
    _usagesDeriveBits,
    'public',
  ));
}

Future<EcdhPublicKey> ecdhPublicKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  EllipticCurve curve,
) async {
  return _EcdhPublicKey(await _importJsonWebKey(
    jwk,
    subtle.Algorithm(
      name: _ecdhAlgorithmName,
      namedCurve: _curveToName(curve),
    ),
    _usagesDeriveBits,
    'public',
  ));
}

class _EcdhPrivateKey implements EcdhPrivateKey {
  final subtle.CryptoKey _key;
  _EcdhPrivateKey(this._key);

  @override
  Future<Uint8List> deriveBits(EcdhPublicKey publicKey, int length) async {
    ArgumentError.checkNotNull(publicKey, 'publicKey');
    if (publicKey is! EcdhPublicKey) {
      throw ArgumentError.value(
        publicKey,
        'publicKey',
        'custom implementations of EcdhPublicKey is not supported',
      );
    }
    return await _deriveBits(
      subtle.Algorithm(
        name: _ecdhAlgorithmName,
        public: (publicKey as _EcdhPublicKey)._key,
      ),
      _key,
      length,
    );
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async {
    return await _exportJsonWebKey(_key);
  }

  @override
  Future<Uint8List> exportPkcs8Key() async {
    return await _exportKey('pkcs8', _key);
  }
}

class _EcdhPublicKey implements EcdhPublicKey {
  final subtle.CryptoKey _key;
  _EcdhPublicKey(this._key);

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async {
    return await _exportJsonWebKey(_key);
  }

  @override
  Future<Uint8List> exportRawKey() async {
    return await _exportKey('raw', _key);
  }

  @override
  Future<Uint8List> exportSpkiKey() async {
    return await _exportKey('spki', _key);
  }
}

//---------------------- HKDF

final _hkdfAlgorithmName = 'HKDF';

Future<HkdfSecretKey> hkdfSecretKey_importRawKey(List<int> keyData) async {
  return await _HkdfSecretKey(await _importKey(
    'raw',
    keyData,
    subtle.Algorithm(name: _hkdfAlgorithmName),
    _usagesDeriveBits,
    'secret',
  ));
}

class _HkdfSecretKey implements HkdfSecretKey {
  final subtle.CryptoKey _key;
  _HkdfSecretKey(this._key);

  @override
  Future<Uint8List> deriveBits(
    int length,
    Hash hash,
    List<int> salt,
    List<int> info,
  ) async {
    ArgumentError.checkNotNull(length, 'length');
    ArgumentError.checkNotNull(salt, 'salt');
    ArgumentError.checkNotNull(info, 'info');
    return await _deriveBits(
      subtle.Algorithm(
        name: _hkdfAlgorithmName,
        hash: _getHashAlgorithm(hash),
        salt: Uint8List.fromList(salt),
        info: Uint8List.fromList(info),
      ),
      _key,
      length,
    );
  }
}

//---------------------- PBKDF2

final _pbkdf2AlgorithmName = 'PBKDF2';

Future<Pbkdf2SecretKey> pbkdf2SecretKey_importRawKey(List<int> keyData) async {
  return await _Pbkdf2SecretKey(await _importKey(
    'raw',
    keyData,
    subtle.Algorithm(name: _pbkdf2AlgorithmName),
    _usagesDeriveBits,
    'secret',
  ));
}

class _Pbkdf2SecretKey implements Pbkdf2SecretKey {
  final subtle.CryptoKey _key;
  _Pbkdf2SecretKey(this._key);

  @override
  Future<Uint8List> deriveBits(
    int length,
    Hash hash,
    List<int> salt,
    int iterations,
  ) async {
    ArgumentError.checkNotNull(length, 'length');
    ArgumentError.checkNotNull(salt, 'salt');
    ArgumentError.checkNotNull(iterations, 'iterations');
    return await _deriveBits(
      subtle.Algorithm(
        name: _pbkdf2AlgorithmName,
        hash: _getHashAlgorithm(hash),
        salt: Uint8List.fromList(salt),
        iterations: iterations,
      ),
      _key,
      length,
    );
  }
}
