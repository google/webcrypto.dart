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

Uint8List _importPkcs8RsaPrivateKey(Uint8List keyData) {
  try {
    return jni.using((arena) {
      final key = _rsaPrivateKeyFromPkcs8(arena, keyData);
      return _copyEncodedRsaKey(arena, key, 'private');
    });
  } on jni.JThrowable catch (e) {
    throw _rsaKeyFormatException(e, 'Unable to import PKCS#8 RSA private key');
  }
}

Uint8List _importSpkiRsaPublicKey(Uint8List keyData) {
  try {
    return jni.using((arena) {
      final key = _rsaPublicKeyFromSpki(arena, keyData);
      return _copyEncodedRsaKey(arena, key, 'public');
    });
  } on jni.JThrowable catch (e) {
    throw _rsaKeyFormatException(e, 'Unable to import SPKI RSA public key');
  }
}

Uint8List _importJwkRsaPrivateKey(
  Map<String, dynamic> jwkData, {
  required String expectedAlg,
  required String expectedUse,
}) {
  final jwk = JsonWebKey.fromJson(jwkData);
  _validateRsaJwk(jwk, expectedAlg: expectedAlg, expectedUse: expectedUse);

  final n = _readRsaJwkInteger(jwk.n, 'n');
  final e = _readRsaJwkInteger(jwk.e, 'e');
  final d = _readRsaJwkInteger(jwk.d, 'd');
  final p = _readRsaJwkInteger(jwk.p, 'p');
  final q = _readRsaJwkInteger(jwk.q, 'q');
  final dp = _readRsaJwkInteger(jwk.dp, 'dp');
  final dq = _readRsaJwkInteger(jwk.dq, 'dq');
  final qi = _readRsaJwkInteger(jwk.qi, 'qi');

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
      key.releasedBy(arena);
      return _copyEncodedRsaKey(arena, key, 'private');
    });
  } on jni.JThrowable catch (e) {
    throw _rsaKeyFormatException(e, 'Unable to import RSA private JWK');
  }
}

Uint8List _importJwkRsaPublicKey(
  Map<String, dynamic> jwkData, {
  required String expectedAlg,
  required String expectedUse,
}) {
  final jwk = JsonWebKey.fromJson(jwkData);
  _validateRsaJwk(jwk, expectedAlg: expectedAlg, expectedUse: expectedUse);

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
      key.releasedBy(arena);
      return _copyEncodedRsaKey(arena, key, 'public');
    });
  } on jni.JThrowable catch (e) {
    throw _rsaKeyFormatException(e, 'Unable to import RSA public JWK');
  }
}

Map<String, dynamic> _exportJwkRsaPrivateKey(
  Uint8List keyData, {
  required String jwkAlg,
  required String jwkUse,
}) {
  try {
    return jni.using((arena) {
      final key = _rsaPrivateKeyFromPkcs8(arena, keyData);
      if (!key.isA(RSAPrivateCrtKey.type)) {
        throw UnsupportedError(
          'The JCA provider does not expose RSA CRT parameters for JWK export',
        );
      }
      final rsaKey = key.as(RSAPrivateCrtKey.type)..releasedBy(arena);

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
        d: _encodeRsaBigInteger(
          arena,
          rsaKey.getPrivateExponent(),
          'private exponent',
        ),
        p: _encodeRsaBigInteger(arena, rsaKey.getPrimeP(), 'prime P'),
        q: _encodeRsaBigInteger(arena, rsaKey.getPrimeQ(), 'prime Q'),
        dp: _encodeRsaBigInteger(
          arena,
          rsaKey.getPrimeExponentP(),
          'prime exponent P',
        ),
        dq: _encodeRsaBigInteger(
          arena,
          rsaKey.getPrimeExponentQ(),
          'prime exponent Q',
        ),
        qi: _encodeRsaBigInteger(
          arena,
          rsaKey.getCrtCoefficient(),
          'CRT coefficient',
        ),
      ).toJson();
    });
  } on jni.JThrowable catch (e) {
    throw _rsaOperationError(e, 'Unable to export RSA private JWK');
  }
}

Map<String, dynamic> _exportJwkRsaPublicKey(
  Uint8List keyData, {
  required String jwkAlg,
  required String jwkUse,
}) {
  try {
    return jni.using((arena) {
      final key = _rsaPublicKeyFromSpki(arena, keyData);
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
  key.releasedBy(arena);
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
  key.releasedBy(arena);
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

String _encodeRsaBigInteger(jni.Arena arena, BigInteger? value, String name) {
  if (value == null) {
    throw AssertionError('JCA RSA key has no $name');
  }
  value.releasedBy(arena);
  final encoded = value.toByteArray();
  if (encoded == null) {
    throw AssertionError(
      'JCA BigInteger.toByteArray() returned null for $name',
    );
  }
  encoded.releasedBy(arena);
  final signedBytes = encoded.copyToDartBytes();
  final unsignedBytes = signedBytes.length > 1 && signedBytes.first == 0
      ? Uint8List.sublistView(signedBytes, 1)
      : signedBytes;
  return _jwkEncodeBase64UrlNoPadding(unsignedBytes);
}

void _validateRsaJwk(
  JsonWebKey jwk, {
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
