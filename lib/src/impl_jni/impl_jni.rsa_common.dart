// Copyright 2026 Google LLC
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

part of 'impl_jni.dart';

typedef _RsaKeyPairData = ({Uint8List privateKeyData, Uint8List publicKeyData});
typedef _RsaPrivateComponents = ({
  BigInt n,
  BigInt e,
  BigInt d,
  BigInt p,
  BigInt q,
  BigInt dp,
  BigInt dq,
  BigInt qi,
});

// Keep import prevalidation aligned with the package-wide key-generation range.
// Providers may impose a stronger minimum when constructing or generating keys.
const _rsaMinModulusBits = 256;
const _rsaMaxModulusBits = 16384;
const _rsaMaxPublicExponentBits = 33;

_HashImpl _rsaHashFromHash(HashImpl hash) {
  if (hash is _HashImpl) {
    return hash;
  }
  throw AssertionError('Custom implementations of HashImpl are not supported.');
}

extension _RsaHashMetadata on _HashImpl {
  String get _rsassaPkcs1v15JcaName {
    return switch (_jcaName) {
      'SHA-1' => 'SHA1withRSA',
      'SHA-256' => 'SHA256withRSA',
      'SHA-384' => 'SHA384withRSA',
      'SHA-512' => 'SHA512withRSA',
      _ => throw AssertionError('Unknown hash algorithm: $_jcaName'),
    };
  }

  String get _rsassaPkcs1v15JwkAlg {
    return switch (_jcaName) {
      'SHA-1' => 'RS1',
      'SHA-256' => 'RS256',
      'SHA-384' => 'RS384',
      'SHA-512' => 'RS512',
      _ => throw AssertionError('Unknown hash algorithm: $_jcaName'),
    };
  }
}

_JcaKeyOwner _importPkcs8RsaPrivateKey(Uint8List keyData) {
  final components = _parsePkcs8RsaPrivateKey(keyData);
  try {
    return jni.using((arena) {
      final key = _rsaPrivateKeyFromPkcs8(arena, keyData);
      return _validateRsaKeyBeforeOwnershipTransfer(
        key,
        () => _validateImportedRsaPrivateKey(arena, key, components),
        rsaPrivateComponents: components,
      );
    });
  } on jni.JThrowable catch (e) {
    throw _rsaKeyFormatException(e, 'Unable to import PKCS#8 RSA private key');
  }
}

_JcaKeyOwner _importSpkiRsaPublicKey(Uint8List keyData) {
  _validateRsaDerEncoding(keyData, 'SPKI RSA public key');
  try {
    return jni.using((arena) {
      final key = _rsaPublicKeyFromSpki(arena, keyData);
      return _validateRsaKeyBeforeOwnershipTransfer(key, () {
        _validateRsaPublicKey(arena, key);
      });
    });
  } on jni.JThrowable catch (e) {
    throw _rsaKeyFormatException(e, 'Unable to import SPKI RSA public key');
  }
}

_JcaKeyOwner _importJwkRsaPrivateKey(
  Map<String, dynamic> jwkData, {
  required String expectedAlg,
  required String expectedUse,
}) {
  final jwk = JsonWebKey.fromJson(jwkData);
  _validateRsaJwk(
    jwk,
    isPrivateKey: true,
    expectedAlg: expectedAlg,
    expectedUse: expectedUse,
  );

  final n = _readRsaJwkInteger(jwk.n, 'n');
  final e = _readRsaJwkInteger(jwk.e, 'e');
  final d = _readRsaJwkInteger(jwk.d, 'd');
  final p = _readRsaJwkInteger(jwk.p, 'p');
  final q = _readRsaJwkInteger(jwk.q, 'q');
  final dp = _readRsaJwkInteger(jwk.dp, 'dp');
  final dq = _readRsaJwkInteger(jwk.dq, 'dq');
  final qi = _readRsaJwkInteger(jwk.qi, 'qi');
  final _RsaPrivateComponents components = (
    n: _rsaBigIntFromBytes(n),
    e: _rsaBigIntFromBytes(e),
    d: _rsaBigIntFromBytes(d),
    p: _rsaBigIntFromBytes(p),
    q: _rsaBigIntFromBytes(q),
    dp: _rsaBigIntFromBytes(dp),
    dq: _rsaBigIntFromBytes(dq),
    qi: _rsaBigIntFromBytes(qi),
  );
  _validateParsedRsaPrivateKey(components);

  try {
    return jni.using((arena) {
      final keyFactory = _rsaKeyFactory(arena);
      final keySpec = RSAPrivateCrtKeySpec(
        _rsaBigInteger(arena, n),
        _rsaBigInteger(arena, e),
        _rsaBigInteger(arena, d),
        _rsaBigInteger(arena, p),
        _rsaBigInteger(arena, q),
        _rsaBigInteger(arena, dp),
        _rsaBigInteger(arena, dq),
        _rsaBigInteger(arena, qi),
      )..releasedBy(arena);
      final key = keyFactory.generatePrivate(keySpec);
      if (key == null) {
        throw AssertionError('JCA RSA KeyFactory returned a null private key');
      }
      return _validateRsaKeyBeforeOwnershipTransfer(
        key,
        () => _validateImportedRsaPrivateKey(arena, key, components),
        rsaPrivateComponents: components,
      );
    });
  } on jni.JThrowable catch (e) {
    throw _rsaKeyFormatException(e, 'Unable to import RSA private JWK');
  }
}

_JcaKeyOwner _importJwkRsaPublicKey(
  Map<String, dynamic> jwkData, {
  required String expectedAlg,
  required String expectedUse,
}) {
  final jwk = JsonWebKey.fromJson(jwkData);
  _validateRsaJwk(
    jwk,
    isPrivateKey: false,
    expectedAlg: expectedAlg,
    expectedUse: expectedUse,
  );

  final n = _readRsaJwkInteger(jwk.n, 'n');
  final e = _readRsaJwkInteger(jwk.e, 'e');

  try {
    return jni.using((arena) {
      final keyFactory = _rsaKeyFactory(arena);
      final keySpec = RSAPublicKeySpec(
        _rsaBigInteger(arena, n),
        _rsaBigInteger(arena, e),
      )..releasedBy(arena);
      final key = keyFactory.generatePublic(keySpec);
      if (key == null) {
        throw AssertionError('JCA RSA KeyFactory returned a null public key');
      }
      return _validateRsaKeyBeforeOwnershipTransfer(key, () {
        _validateRsaPublicKey(arena, key);
      });
    });
  } on jni.JThrowable catch (e) {
    throw _rsaKeyFormatException(e, 'Unable to import RSA public JWK');
  }
}

_JcaKeyOwner _validateRsaKeyBeforeOwnershipTransfer(
  jni.JObject key,
  void Function() validate, {
  _RsaPrivateComponents? rsaPrivateComponents,
}) {
  try {
    validate();
    return _JcaKeyOwner(key, rsaPrivateComponents: rsaPrivateComponents);
  } catch (_) {
    // The key is not persistent until ownership transfers to a Dart wrapper.
    key.release();
    rethrow;
  }
}

Uint8List _exportEncodedRsaKey(_JcaKeyOwner owner, String keyType) {
  try {
    return jni.using((arena) => _copyEncodedRsaKey(arena, owner.key, keyType));
  } on jni.JThrowable catch (e) {
    throw _rsaOperationError(e, 'Unable to export RSA $keyType key');
  }
}

Map<String, dynamic> _exportJwkRsaPrivateKey(
  _JcaKeyOwner owner, {
  required String jwkAlg,
  required String jwkUse,
}) {
  final c = owner.rsaPrivateComponents;
  if (c == null) {
    throw StateError('RSA private key components are unavailable');
  }
  String encode(BigInt value) =>
      _jwkEncodeBase64UrlNoPadding(_unsignedBytesFromBigInt(value));
  return JsonWebKey(
    kty: 'RSA',
    use: jwkUse,
    alg: jwkAlg,
    n: encode(c.n),
    e: encode(c.e),
    d: encode(c.d),
    p: encode(c.p),
    q: encode(c.q),
    dp: encode(c.dp),
    dq: encode(c.dq),
    qi: encode(c.qi),
  ).toJson();
}

Map<String, dynamic> _exportJwkRsaPublicKey(
  _JcaKeyOwner owner, {
  required String jwkAlg,
  required String jwkUse,
}) {
  try {
    return jni.using((arena) {
      final key = owner.key;
      if (!key.isA(RSAPublicKey.type)) {
        throw AssertionError(
          'JCA RSA KeyFactory returned a non-RSA public key',
        );
      }
      final rsaKey = key.as(RSAPublicKey.type)..releasedBy(arena);

      return JsonWebKey(
        kty: 'RSA',
        use: jwkUse,
        alg: jwkAlg,
        n: _encodeRsaBigInteger(arena, rsaKey.getModulus(), 'modulus'),
        e: _encodeRsaBigInteger(
          arena,
          rsaKey.getPublicExponent(),
          'public exponent',
        ),
      ).toJson();
    });
  } on jni.JThrowable catch (e) {
    throw _rsaOperationError(e, 'Unable to export RSA public JWK');
  }
}

Future<_RsaKeyPairData> _generateRsaKeyPair(
  int modulusLength,
  BigInt publicExponent,
) async {
  _validateRsaKeyGenerationParameters(modulusLength, publicExponent);
  return Isolate.run(
    () => _generateRsaKeyPairOnCurrentIsolate(modulusLength, publicExponent),
    debugName: 'JCA RSA key generation',
  );
}

_RsaKeyPairData _generateRsaKeyPairOnCurrentIsolate(
  int modulusLength,
  BigInt publicExponent,
) {
  try {
    return jni.using((arena) {
      final algorithm = 'RSA'.toJString()..releasedBy(arena);
      final generator = KeyPairGenerator.getInstance(algorithm);
      if (generator == null) {
        throw AssertionError('JCA RSA KeyPairGenerator returned null');
      }
      generator.releasedBy(arena);

      final exponent = _rsaBigInteger(
        arena,
        _unsignedBytesFromBigInt(publicExponent),
      );
      final parameters = RSAKeyGenParameterSpec(modulusLength, exponent)
        ..releasedBy(arena);
      generator.initialize$2(parameters);

      final pair = generator.generateKeyPair();
      if (pair == null) {
        throw AssertionError('JCA RSA KeyPairGenerator returned null key pair');
      }
      pair.releasedBy(arena);

      final privateKey = pair.private;
      final publicKey = pair.public;
      if (privateKey == null || publicKey == null) {
        throw AssertionError('JCA RSA key pair contains a null key');
      }
      privateKey.releasedBy(arena);
      publicKey.releasedBy(arena);

      return (
        privateKeyData: _copyEncodedRsaKey(arena, privateKey, 'private'),
        publicKeyData: _copyEncodedRsaKey(arena, publicKey, 'public'),
      );
    });
  } on jni.JThrowable catch (e) {
    throw _rsaOperationError(e, 'JCA RSA key generation failed');
  }
}

jni.JObject _rsaPrivateKeyFromPkcs8(jni.Arena arena, Uint8List keyData) {
  final keyFactory = _rsaKeyFactory(arena);
  final encoded = arena.copyToJByteArray(keyData);
  final keySpec = PKCS8EncodedKeySpec(encoded)..releasedBy(arena);
  final key = keyFactory.generatePrivate(keySpec);
  if (key == null) {
    throw AssertionError('JCA RSA KeyFactory returned a null private key');
  }
  // Ownership transfers to the Dart key wrapper, so this reference must not
  // be registered with the temporary arena.
  return key;
}

jni.JObject _rsaPublicKeyFromSpki(jni.Arena arena, Uint8List keyData) {
  final keyFactory = _rsaKeyFactory(arena);
  final encoded = arena.copyToJByteArray(keyData);
  final keySpec = X509EncodedKeySpec(encoded)..releasedBy(arena);
  final key = keyFactory.generatePublic(keySpec);
  if (key == null) {
    throw AssertionError('JCA RSA KeyFactory returned a null public key');
  }
  // Ownership transfers to the Dart key wrapper, so this reference must not
  // be registered with the temporary arena.
  return key;
}

KeyFactory _rsaKeyFactory(jni.Arena arena) {
  final algorithm = 'RSA'.toJString()..releasedBy(arena);
  final keyFactory = KeyFactory.getInstance(algorithm);
  if (keyFactory == null) {
    throw AssertionError('JCA RSA KeyFactory returned null');
  }
  keyFactory.releasedBy(arena);
  return keyFactory;
}

Uint8List _copyEncodedRsaKey(jni.Arena arena, jni.JObject key, String keyType) {
  final jcaKey = key.as(Key.type)..releasedBy(arena);
  final encoded = jcaKey.getEncoded();
  if (encoded == null) {
    throw AssertionError('JCA RSA $keyType key has no encoded form');
  }
  encoded.releasedBy(arena);
  return encoded.copyToDartBytes();
}

BigInteger _rsaBigInteger(jni.Arena arena, Uint8List unsignedBytes) {
  final bytes = arena.copyToJByteArray(unsignedBytes);
  return BigInteger.new$3(1, bytes)..releasedBy(arena);
}

void _validateImportedRsaPrivateKey(
  jni.Arena arena,
  jni.JObject key,
  _RsaPrivateComponents components,
) {
  _checkData(
    key.isA(RSAPrivateKey.type),
    'Invalid RSA private key: RSA parameters are required',
  );
  final rsaKey = key.as(RSAPrivateKey.type)..releasedBy(arena);
  _checkData(
    _readPositiveRsaBigInteger(arena, rsaKey.getModulus(), 'n') ==
            components.n &&
        _readPositiveRsaBigInteger(arena, rsaKey.getPrivateExponent(), 'd') ==
            components.d,
    'Invalid RSA private key: provider changed the imported key',
  );
}

_RsaPrivateComponents _parsePkcs8RsaPrivateKey(Uint8List data) {
  final outer = _DerReader(data);
  final info = _DerReader(outer.readElement(0x30));
  outer.expectDone();
  _checkData(
    _readRsaDerInteger(info, 'PKCS#8 version') == BigInt.zero,
    'Invalid PKCS#8 RSA private key: unsupported version',
  );
  final algorithm = _DerReader(info.readElement(0x30));
  // rsaEncryption (1.2.840.113549.1.1.1) with NULL parameters.
  const rsaOid = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
  final oid = algorithm.readElement(0x06);
  _checkData(
    _bytesEqual(oid, Uint8List.fromList(rsaOid)),
    'Invalid PKCS#8 RSA algorithm',
  );
  _checkData(
    algorithm.readElement(0x05).isEmpty,
    'Invalid PKCS#8 RSA algorithm parameters',
  );
  algorithm.expectDone();
  final wrapped = _DerReader(info.readElement(0x04));
  if (!info.isDone) {
    // PKCS#8 permits optional attributes after the private key.
    info.readElement(0xa0);
  }
  info.expectDone();
  final rsa = _DerReader(wrapped.readElement(0x30));
  wrapped.expectDone();
  _checkData(
    _readRsaDerInteger(rsa, 'RSA version') == BigInt.zero,
    'Invalid RSA private key: multi-prime keys are unsupported',
  );
  final components = (
    n: _readRsaDerInteger(rsa, 'n'),
    e: _readRsaDerInteger(rsa, 'e'),
    d: _readRsaDerInteger(rsa, 'd'),
    p: _readRsaDerInteger(rsa, 'p'),
    q: _readRsaDerInteger(rsa, 'q'),
    dp: _readRsaDerInteger(rsa, 'dp'),
    dq: _readRsaDerInteger(rsa, 'dq'),
    qi: _readRsaDerInteger(rsa, 'qi'),
  );
  rsa.expectDone();
  _validateParsedRsaPrivateKey(components);
  return components;
}

BigInt _readRsaDerInteger(_DerReader reader, String name) {
  final bytes = reader.readElement(0x02);
  _checkData(
    bytes.isNotEmpty && bytes.first & 0x80 == 0,
    'Invalid RSA private key: $name must be nonnegative',
  );
  _checkData(
    bytes.length == 1 || bytes.first != 0 || bytes[1] & 0x80 != 0,
    'Invalid RSA private key: $name has non-minimal encoding',
  );
  return _rsaBigIntFromBytes(bytes);
}

BigInt _rsaBigIntFromBytes(List<int> bytes) {
  var value = BigInt.zero;
  for (final byte in bytes) {
    value = (value << 8) | BigInt.from(byte);
  }
  return value;
}

void _validateParsedRsaPrivateKey(_RsaPrivateComponents c) {
  _validateRsaPrivateComponents(
    n: c.n,
    e: c.e,
    d: c.d,
    p: c.p,
    q: c.q,
    dp: c.dp,
    dq: c.dq,
    qi: c.qi,
  );
  // BigInt has no primality test; reject composites before handing the key
  // to a provider that may defer its own consistency checks.
  jni.using((arena) {
    for (final prime in [c.p, c.q]) {
      final value = _rsaBigInteger(arena, _unsignedBytesFromBigInt(prime));
      _checkData(
        value.isProbablePrime(100),
        'Invalid RSA private key: p or q is not prime',
      );
    }
  });
}

void _validateRsaPublicKey(jni.Arena arena, jni.JObject key) {
  _checkData(
    key.isA(RSAPublicKey.type),
    'Invalid RSA public key: RSA parameters are required',
  );
  final rsaKey = key.as(RSAPublicKey.type)..releasedBy(arena);
  _validateRsaPublicComponents(
    n: _readPositiveRsaBigInteger(arena, rsaKey.getModulus(), 'n'),
    e: _readPositiveRsaBigInteger(arena, rsaKey.getPublicExponent(), 'e'),
  );
}

BigInt _readPositiveRsaBigInteger(
  jni.Arena arena,
  BigInteger? value,
  String name,
) {
  _checkData(value != null, 'Invalid RSA key: $name is missing');
  value!.releasedBy(arena);
  _checkData(value.signum() > 0, 'Invalid RSA key: $name must be positive');
  final bytes = _copyUnsignedRsaBigInteger(arena, value, name);
  var result = BigInt.zero;
  for (final byte in bytes) {
    result = (result << 8) | BigInt.from(byte);
  }
  return result;
}

Uint8List _copyUnsignedRsaBigInteger(
  jni.Arena arena,
  BigInteger value,
  String name,
) {
  final encoded = value.toByteArray();
  if (encoded == null) {
    throw AssertionError(
      'JCA BigInteger.toByteArray() returned null for $name',
    );
  }
  encoded.releasedBy(arena);
  final signedBytes = encoded.copyToDartBytes();
  final start = signedBytes.length > 1 && signedBytes.first == 0 ? 1 : 0;
  return Uint8List.sublistView(signedBytes, start);
}

void _validateRsaPrivateComponents({
  required BigInt n,
  required BigInt e,
  required BigInt d,
  required BigInt p,
  required BigInt q,
  required BigInt dp,
  required BigInt dq,
  required BigInt qi,
}) {
  // Validate the two-prime RSA relationships from PKCS #1. The corresponding
  // JWK fields are defined by JSON Web Algorithms:
  // https://www.rfc-editor.org/rfc/rfc8017#section-3.2
  // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.2
  // The FFI backend checks the same relationships with RSA_check_key(); see:
  // third_party/boringssl/src/crypto/fipsmodule/rsa/rsa.cc.inc
  final one = BigInt.one;
  _validateRsaPublicComponents(n: n, e: e);
  _checkData(
    p > one && q > one,
    'Invalid RSA private key: p and q must be greater than one',
  );
  _checkData(p != q, 'Invalid RSA private key: p and q must differ');
  _checkData(
    p.isOdd && q.isOdd,
    'Invalid RSA private key: p and q must be odd',
  );
  _checkData(n == p * q, 'Invalid RSA private key: n does not equal p * q');
  _checkData(d > one && d < n, 'Invalid RSA private key: invalid d');

  final pMinusOne = p - one;
  final qMinusOne = q - one;
  final lambda = (pMinusOne ~/ pMinusOne.gcd(qMinusOne)) * qMinusOne;
  _checkData(
    (d * e) % lambda == one,
    'Invalid RSA private key: d and e are inconsistent',
  );
  _checkData(dp == d % pMinusOne, 'Invalid RSA private key: invalid dp');
  _checkData(dq == d % qMinusOne, 'Invalid RSA private key: invalid dq');
  _checkData(
    q.gcd(p) == one,
    'Invalid RSA private key: p and q are not coprime',
  );
  _checkData(qi == q.modInverse(p), 'Invalid RSA private key: invalid qi');
}

void _validateRsaPublicComponents({required BigInt n, required BigInt e}) {
  final one = BigInt.one;
  _checkData(
    n.bitLength >= _rsaMinModulusBits &&
        n.bitLength <= _rsaMaxModulusBits &&
        n.isOdd,
    'Invalid RSA public key: invalid n',
  );
  _checkData(
    e > one && e.isOdd && e.bitLength <= _rsaMaxPublicExponentBits && e < n,
    'Invalid RSA public key: invalid e',
  );
}

String _encodeRsaBigInteger(jni.Arena arena, BigInteger? value, String name) {
  if (value == null) {
    throw AssertionError('JCA RSA key has no $name');
  }
  value.releasedBy(arena);
  return _jwkEncodeBase64UrlNoPadding(
    _copyUnsignedRsaBigInteger(arena, value, name),
  );
}

void _validateRsaJwk(
  JsonWebKey jwk, {
  required bool isPrivateKey,
  required String expectedAlg,
  required String expectedUse,
}) {
  void check(bool condition, String prop, String message) {
    _checkData(condition, 'JWK property "$prop" $message');
  }

  check(jwk.kty == 'RSA', 'kty', 'must be "RSA"');
  check(
    jwk.alg == null || jwk.alg == expectedAlg,
    'alg',
    'must be "$expectedAlg", if present',
  );
  check(
    jwk.use == null || jwk.use == expectedUse,
    'use',
    'must be "$expectedUse", if present',
  );
  check(
    isPrivateKey ? jwk.d != null : jwk.d == null,
    'd',
    isPrivateKey
        ? 'must be present for a private key'
        : 'must not be present for a public key',
  );
}

Uint8List _readRsaJwkInteger(String? value, String prop) {
  _checkData(value != null, 'JWK property "$prop" must be present');
  final bytes = _jwkDecodeBase64UrlNoPadding(value!, prop);
  _checkData(bytes.isNotEmpty, 'JWK property "$prop" must not be empty');
  _checkData(
    bytes.length == 1 || bytes.first != 0,
    'JWK property "$prop" must not have leading zeros',
  );
  return bytes;
}

Uint8List _unsignedBytesFromBigInt(BigInt value) {
  if (value <= BigInt.zero) {
    throw ArgumentError.value(value, 'value', 'must be positive');
  }
  final bytes = <int>[];
  var remaining = value;
  while (remaining > BigInt.zero) {
    bytes.add((remaining & BigInt.from(0xff)).toInt());
    remaining >>= 8;
  }
  return Uint8List.fromList(bytes.reversed.toList());
}

void _validateRsaKeyGenerationParameters(
  int modulusLength,
  BigInt publicExponent,
) {
  if (modulusLength < 256 || modulusLength > 16384) {
    throw UnsupportedError(
      'modulusLength must be between 256 and 16384 bits; '
      '$modulusLength is not supported',
    );
  }
  if (modulusLength % 8 != 0) {
    throw UnsupportedError('modulusLength must be a multiple of 8');
  }
  if (publicExponent != BigInt.from(3) &&
      publicExponent != BigInt.from(65537)) {
    throw UnsupportedError('publicExponent is not supported; use 3 or 65537');
  }
}

void _validateRsaDerEncoding(Uint8List keyData, String name) {
  // JCA KeyFactory accepts a valid key followed by unused bytes. Check the
  // outer DER sequence length so the entire caller-provided input is consumed.
  _checkData(
    keyData.length >= 2 && keyData.first == 0x30,
    '$name must be a DER-encoded sequence',
  );

  final firstLengthByte = keyData[1];
  var headerLength = 2;
  var contentLength = 0;
  if (firstLengthByte < 0x80) {
    contentLength = firstLengthByte;
  } else {
    final lengthByteCount = firstLengthByte & 0x7f;
    _checkData(lengthByteCount != 0, '$name uses an indefinite DER length');
    _checkData(
      lengthByteCount <= keyData.length - 2,
      '$name has a truncated DER length',
    );
    _checkData(keyData[2] != 0, '$name has a non-minimal DER length');
    headerLength += lengthByteCount;
    for (var i = 0; i < lengthByteCount; i++) {
      contentLength = (contentLength << 8) | keyData[2 + i];
    }
    _checkData(contentLength >= 0x80, '$name has a non-minimal DER length');
  }

  _checkData(
    headerLength + contentLength == keyData.length,
    '$name has trailing or truncated data',
  );
}

FormatException _rsaKeyFormatException(
  jni.JThrowable throwable,
  String context,
) {
  final message = _rsaThrowableMessage(throwable);
  return FormatException('$context: $message');
}

OperationError _rsaOperationError(jni.JThrowable throwable, String context) {
  final message = _rsaThrowableMessage(throwable);
  return operationError('$context: $message');
}

String _rsaThrowableMessage(jni.JThrowable throwable) {
  late final String message;
  try {
    message = throwable.message;
  } finally {
    throwable.release();
  }
  return message;
}
