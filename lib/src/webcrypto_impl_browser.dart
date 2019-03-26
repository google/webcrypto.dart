import '../webcrypto.dart';
import 'dart:async';
import 'crypto_subtle.dart' as subtle;
import 'utils.dart' as utils;
import 'dart:typed_data';
import 'dart:html' show DomException;

Object _asErrorOrException(DomException e) {
  switch (e.name) {
    case 'NotSupportedError':
      return NotSupportedException(e.message);
    case 'SyntaxError':
      // SyntaxError is thrown as ArgumentError
      return ArgumentError(e.message);
    case 'InvalidAccessError':
      // InvalidAccessError is thrown as StateError
      return StateError(e.message);
    case 'DataError':
      return DataException(e.message);
    case 'OperationError':
      return OperationException(e.message);
    case 'QuotaExceededError':
      return ArgumentError(e.message);
  }
  return AssertionError('Unexpected exception from web cryptography'
      '"${e.name}", message: ${e.message}');
}

/// Handle instances of [subtle.DomException] specified in the
/// [Web Cryptograpy specification][1].
///
/// [1]: https://www.w3.org/TR/WebCryptoAPI/#SubtleCrypto-Exceptions
Future<T> _catchDomException<T>(Future<T> Function() fn) async {
  try {
    return await fn();
  } on DomException catch (e) {
    throw _asErrorOrException(e);
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

/// BaseClass for [CryptoKey] subclasses wrapping a [subtle.CryptoKey].
abstract class _BrowserCryptoKeyBase implements CryptoKey {
  /// CryptoKey object being wrapped.
  final subtle.CryptoKey _key;

  _BrowserCryptoKeyBase(this._key) {
    assert(_key != null, 'expected a key, instead got "null"'); // sanity check
  }

  @override
  bool get extractable => _key.extractable;

  @override
  List<KeyUsage> get usages => subtle.stringsToKeyUsages(_key.usages);
}

//---------------------- Wrappers

/// Adapt `crypto.subtle.importKey` to dart types.
Future<subtle.CryptoKey> _importKey(
  String format,
  List<int> keyData,
  subtle.Algorithm algorithm,
  bool extractable,
  List<KeyUsage> usages,
) {
  return _catchDomException(() async {
    return subtle.promiseAsFuture(subtle.importKey(
      format,
      Uint8List.fromList(keyData),
      algorithm,
      extractable,
      subtle.keyUsagesToStrings(usages),
    ));
  });
}

/// Adapt `crypto.subtle.sign` to dart types.
Future<List<int>> _sign(
  subtle.Algorithm algorithm,
  subtle.CryptoKey key,
  Stream<List<int>> data,
) {
  ArgumentError.checkNotNull(data, 'data');

  return _catchDomException(() async {
    final result = await subtle.promiseAsFuture(subtle.sign(
      algorithm,
      key,
      await utils.asBuffer(data),
    ));
    return result.asUint8List();
  });
}

/// Adapt `crypto.subtle.verify` to dart types.
Future<bool> _verify(
  subtle.Algorithm algorithm,
  subtle.CryptoKey key,
  List<int> signature,
  Stream<List<int>> data,
) {
  ArgumentError.checkNotNull(signature, 'signature');
  ArgumentError.checkNotNull(data, 'data');

  return _catchDomException(() async {
    return await subtle.promiseAsFuture(subtle.verify(
      algorithm,
      key,
      Uint8List.fromList(signature),
      await utils.asBuffer(data),
    ));
  });
}

/// Adapt `crypto.subtle.export` to dart types.
Future<List<int>> _exportKey(
  String format,
  subtle.CryptoKey key,
) {
  ArgumentError.checkNotNull(format, 'format');

  return _catchDomException(() async {
    final result = await subtle.promiseAsFuture(subtle.exportKey(format, key));
    return result.asUint8List();
  });
}

/// Adapt `crypto.subtle.generateKey` to dart types.
Future<subtle.CryptoKey> _generateKey(
  subtle.Algorithm algorithm,
  bool extractable,
  List<KeyUsage> usages,
) {
  return _catchDomException(() async {
    return subtle.promiseAsFuture(subtle.generateKey(
      algorithm,
      extractable,
      subtle.keyUsagesToStrings(usages),
    ));
  });
}

/// Adapt `crypto.subtle.generateKey` to dart types.
Future<subtle.CryptoKeyPair> _generateKeyPair(
  subtle.Algorithm algorithm,
  bool extractable,
  List<KeyUsage> usages,
) {
  return _catchDomException(() async {
    return subtle.promiseAsFuture(subtle.generateKeyPair(
      algorithm,
      extractable,
      subtle.keyUsagesToStrings(usages),
    ));
  });
}

//---------------------- Random Bytes

void getRandomValues(TypedData destination) {
  try {
    subtle.getRandomValues(destination);
  } on DomException catch (e) {
    throw _asErrorOrException(e);
  }
}

//---------------------- HashAlgorithms

/// Wrap `crypto.subtle.digest`.
Future<List<int>> digest({HashAlgorithm hash, Stream<List<int>> data}) {
  return _catchDomException(() async {
    final algorithm = subtle.hashAlgorithmToString(hash);
    final input = await utils.asBuffer(data);

    final result = await subtle.promiseAsFuture(subtle.digest(
      algorithm,
      input,
    ));
    return result.asUint8List();
  });
}

//---------------------- HMAC

final _hmacAlgorithm = subtle.Algorithm(name: 'HMAC');

/// Wrap `crypto.subtle.importKey` for use in importing keys with the `HMAC`
/// algorithm, and return the result wrapped as [HmacSecretKey].
Future<HmacSecretKey> hmacSecret_importRawKey({
  List<int> keyData,
  bool extractable,
  List<KeyUsage> usages,
  HashAlgorithm hash,
  int length,
}) async {
  // Construct object with algorithm specific options
  subtle.Algorithm algorithm;
  if (length == null) {
    algorithm = subtle.Algorithm(
      name: 'HMAC',
      hash: subtle.hashAlgorithmToString(hash),
    );
  } else {
    algorithm = subtle.Algorithm(
      name: 'HMAC',
      hash: subtle.hashAlgorithmToString(hash),
      length: length,
    );
  }

  final k = await _importKey('raw', keyData, algorithm, extractable, usages);
  assert(k.type == 'secret', 'expected a "secret" key');
  return _HmacSecretKey(k);
}

Future<HmacSecretKey> hmacSecret_generateKey({
  bool extractable,
  List<KeyUsage> usages,
  HashAlgorithm hash,
  int length,
}) async {
  // Construct object with algorithm specific options
  subtle.Algorithm algorithm;
  if (length == null) {
    algorithm = subtle.Algorithm(
      name: 'HMAC',
      hash: subtle.hashAlgorithmToString(hash),
    );
  } else {
    algorithm = subtle.Algorithm(
      name: 'HMAC',
      hash: subtle.hashAlgorithmToString(hash),
      length: length,
    );
  }

  final k = await _generateKey(algorithm, extractable, usages);
  assert(k.type == 'secret', 'expected a "secret" key');
  return _HmacSecretKey(k);
}

class _HmacSecretKey extends _BrowserCryptoKeyBase implements HmacSecretKey {
  _HmacSecretKey(subtle.CryptoKey key) : super(key);

  @override
  Future<List<int>> sign({Stream<List<int>> data}) {
    return _sign(_hmacAlgorithm, _key, data);
  }

  @override
  Future<bool> verify({List<int> signature, Stream<List<int>> data}) {
    return _verify(_hmacAlgorithm, _key, signature, data);
  }

  @override
  Future<List<int>> exportRawKey() {
    return _exportKey('raw', _key);
  }
}

//---------------------- RSASSA_PKCS1_v1_5

final _rsassaPkcs1V15Algorithm = subtle.Algorithm(name: 'RSASSA-PKCS1-v1_5');

Future<RsassaPkcs1V15PrivateKey> rsassaPkcs1V15PrivateKey_importPkcs8Key({
  List<int> keyData,
  bool extractable,
  List<KeyUsage> usages,
  HashAlgorithm hash,
}) async {
  final algorithm = subtle.Algorithm(
    name: _rsassaPkcs1V15Algorithm.name,
    hash: subtle.hashAlgorithmToString(hash),
  );

  final k = await _importKey('pkcs8', keyData, algorithm, extractable, usages);

  // Ensure that we have a private key
  if (k.type != 'private') {
    throw ArgumentError.value(keyData, 'keyData',
        'must be a "private" key, instead we got a "${k.type}" key');
  }

  return _RsassaPkcs1V15PrivateKey(k);
}

Future<RsassaPkcs1V15PublicKey> rsassaPkcs1V15PublicKey_importSpkiKey({
  List<int> keyData,
  bool extractable,
  List<KeyUsage> usages,
  HashAlgorithm hash,
}) async {
  final algorithm = subtle.Algorithm(
    name: _rsassaPkcs1V15Algorithm.name,
    hash: subtle.hashAlgorithmToString(hash),
  );

  final k = await _importKey('spki', keyData, algorithm, extractable, usages);

  // Ensure that we have a private key
  if (k.type != 'private') {
    throw ArgumentError.value(keyData, 'keyData',
        'must be a "private" key, instead we got a "${k.type}" key');
  }

  return _RsassaPkcs1V15PublicKey(k);
}

Future<CryptoKeyPair<RsassaPkcs1V15PrivateKey, RsassaPkcs1V15PublicKey>>
    rsassaPkcs1V15PrivateKey_generateKey({
  int modulusLength,
  BigInt publicExponent,
  HashAlgorithm hash,
  bool extractable,
  List<KeyUsage> usages,
}) async {
  final algorithm = subtle.Algorithm(
    name: _rsassaPkcs1V15Algorithm.name,
    hash: subtle.hashAlgorithmToString(hash),
    publicExponent: subtle.bigIntToUint8ListBigInteger(publicExponent),
    modulusLength: modulusLength,
  );

  final pair = await _generateKeyPair(algorithm, extractable, usages);
  // Sanity check the generated keys
  assert(pair.privateKey.type == 'private');
  assert(pair.publicKey.type == 'public');

  return _CryptoKeyPair(
    _RsassaPkcs1V15PrivateKey(pair.privateKey),
    _RsassaPkcs1V15PublicKey(pair.publicKey),
  );
}

class _RsassaPkcs1V15PrivateKey extends _BrowserCryptoKeyBase
    implements RsassaPkcs1V15PrivateKey {
  _RsassaPkcs1V15PrivateKey(subtle.CryptoKey key) : super(key);

  @override
  Future<List<int>> sign({Stream<List<int>> data}) {
    return _sign(_rsassaPkcs1V15Algorithm, _key, data);
  }

  @override
  Future<List<int>> exportPkcs8Key() {
    return _exportKey('pkcs8', _key);
  }
}

class _RsassaPkcs1V15PublicKey extends _BrowserCryptoKeyBase
    implements RsassaPkcs1V15PublicKey {
  _RsassaPkcs1V15PublicKey(subtle.CryptoKey key) : super(key);

  @override
  Future<bool> verify({List<int> signature, Stream<List<int>> data}) {
    return _verify(_rsassaPkcs1V15Algorithm, _key, signature, data);
  }

  @override
  Future<List<int>> exportSpkiKey() {
    return _exportKey('spki', _key);
  }
}
