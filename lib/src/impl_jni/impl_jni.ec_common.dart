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

typedef _EcPointBytes = ({Uint8List x, Uint8List y});
typedef _EcKeyPairData = ({Uint8List privateKeyData, Uint8List publicKeyData});

// Prime-field parameters for the supported NIST curves, from SEC 2 v2,
// sections 2.4.2, 2.5.1, and 2.6.1: https://www.secg.org/sec2-v2.pdf
final _p256Prime = BigInt.parse(
  'ffffffff00000001000000000000000000000000ffffffffffffffffffffffff',
  radix: 16,
);
final _p256B = BigInt.parse(
  '5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b',
  radix: 16,
);
final _p384Prime = BigInt.parse(
  'fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe'
  'ffffffff0000000000000000ffffffff',
  radix: 16,
);
final _p384B = BigInt.parse(
  'b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875a'
  'c656398d8a2ed19d2a85c8edd3ec2aef',
  radix: 16,
);
final _p521Prime = (BigInt.one << 521) - BigInt.one;
final _p521B = BigInt.parse(
  '0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef'
  '109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b5'
  '03f00',
  radix: 16,
);

final class _EcPrivateKeyMaterial {
  _EcPrivateKeyMaterial(this.owner, this.curve, this.publicPoint);

  final _JcaKeyOwner owner;
  final EllipticCurve curve;
  final _EcPointBytes publicPoint;
}

final class _EcPublicKeyMaterial {
  _EcPublicKeyMaterial(this.owner, this.curve, this.point);

  final _JcaKeyOwner owner;
  final EllipticCurve curve;
  final _EcPointBytes point;
}

extension _EcCurveMetadata on EllipticCurve {
  String get _jcaName {
    return switch (this) {
      EllipticCurve.p256 => 'secp256r1',
      EllipticCurve.p384 => 'secp384r1',
      EllipticCurve.p521 => 'secp521r1',
    };
  }

  String get _jwkCrv {
    return switch (this) {
      EllipticCurve.p256 => 'P-256',
      EllipticCurve.p384 => 'P-384',
      EllipticCurve.p521 => 'P-521',
    };
  }

  int get _coordinateLength {
    return switch (this) {
      EllipticCurve.p256 => 32,
      EllipticCurve.p384 => 48,
      EllipticCurve.p521 => 66,
    };
  }

  ({BigInt prime, BigInt b}) get _primeCurveParameters {
    return switch (this) {
      EllipticCurve.p256 => (prime: _p256Prime, b: _p256B),
      EllipticCurve.p384 => (prime: _p384Prime, b: _p384B),
      EllipticCurve.p521 => (prime: _p521Prime, b: _p521B),
    };
  }
}

Future<_EcKeyPairData> _generateEcKeyPair(EllipticCurve curve) {
  return Isolate.run(
    () => _generateEcKeyPairOnCurrentIsolate(curve),
    debugName: 'JCA EC key generation',
  );
}

_EcKeyPairData _generateEcKeyPairOnCurrentIsolate(EllipticCurve curve) {
  try {
    return jni.using((arena) {
      final algorithm = 'EC'.toJString()..releasedBy(arena);
      final generator = KeyPairGenerator.getInstance(algorithm);
      if (generator == null) {
        throw AssertionError('JCA EC KeyPairGenerator returned null');
      }
      generator.releasedBy(arena);

      final curveName = curve._jcaName.toJString()..releasedBy(arena);
      final parameters = ECGenParameterSpec(curveName)..releasedBy(arena);
      generator.initialize$2(parameters);

      final pair = generator.generateKeyPair();
      if (pair == null) {
        throw AssertionError('JCA EC KeyPairGenerator returned null key pair');
      }
      pair.releasedBy(arena);

      final privateKey = pair.private;
      final publicKey = pair.public;
      if (privateKey == null || publicKey == null) {
        throw AssertionError('JCA EC key pair contains a null key');
      }
      privateKey.releasedBy(arena);
      publicKey.releasedBy(arena);

      return (
        privateKeyData: _copyEncodedEcKey(arena, privateKey, 'private'),
        publicKeyData: _copyEncodedEcKey(arena, publicKey, 'public'),
      );
    });
  } on jni.JThrowable catch (e) {
    throw _ecOperationError(e, 'JCA EC key generation failed');
  }
}

_EcPrivateKeyMaterial _importPkcs8EcPrivateKey(
  Uint8List keyData,
  EllipticCurve curve, {
  _EcPointBytes? publicPoint,
}) {
  _validateEcDerSequence(keyData, 'PKCS#8 EC private key');
  final encodedPoint =
      publicPoint ?? _extractEcPublicPointFromPkcs8(keyData, curve);

  try {
    return jni.using((arena) {
      final keyFactory = _ecKeyFactory(arena);
      final encoded = arena.copyToJByteArray(keyData);
      final keySpec = PKCS8EncodedKeySpec(encoded)..releasedBy(arena);
      final key = keyFactory.generatePrivate(keySpec);
      if (key == null) {
        throw AssertionError('JCA EC KeyFactory returned a null private key');
      }

      return _validateEcKeyBeforeOwnershipTransfer(key, () {
        _validateEcPrivateKey(arena, key, curve);
        final point = encodedPoint ?? _deriveEcPublicPoint(arena, key, curve);
        if (encodedPoint != null) {
          _validateEcPrivatePublicPair(arena, key, point, curve);
        }
        return _EcPrivateKeyMaterial(_JcaKeyOwner(key), curve, point);
      });
    });
  } on jni.JThrowable catch (e) {
    throw _ecKeyFormatException(e, 'Unable to import PKCS#8 EC private key');
  }
}

_EcPublicKeyMaterial _importSpkiEcPublicKey(
  Uint8List keyData,
  EllipticCurve curve,
) {
  _validateEcDerSequence(keyData, 'SPKI EC public key');
  try {
    return jni.using((arena) {
      final keyFactory = _ecKeyFactory(arena);
      final encoded = arena.copyToJByteArray(keyData);
      final keySpec = X509EncodedKeySpec(encoded)..releasedBy(arena);
      final key = keyFactory.generatePublic(keySpec);
      if (key == null) {
        throw AssertionError('JCA EC KeyFactory returned a null public key');
      }

      return _validateEcKeyBeforeOwnershipTransfer(key, () {
        final point = _validateEcPublicKey(arena, key, curve);
        return _EcPublicKeyMaterial(_JcaKeyOwner(key), curve, point);
      });
    });
  } on jni.JThrowable catch (e) {
    throw _ecKeyFormatException(e, 'Unable to import SPKI EC public key');
  }
}

_EcPublicKeyMaterial _importRawEcPublicKey(
  Uint8List keyData,
  EllipticCurve curve,
) {
  final point = _decodeRawEcPoint(keyData, curve);
  try {
    return jni.using((arena) {
      final key = _ecPublicKeyFromPoint(arena, point, curve);
      return _validateEcKeyBeforeOwnershipTransfer(key, () {
        final actualPoint = _validateEcPublicKey(arena, key, curve);
        _checkData(
          _ecPointsEqual(point, actualPoint),
          'Invalid EC public key coordinates',
        );
        return _EcPublicKeyMaterial(_JcaKeyOwner(key), curve, actualPoint);
      });
    });
  } on jni.JThrowable catch (e) {
    throw _ecKeyFormatException(e, 'Unable to import raw EC public key');
  }
}

_EcPrivateKeyMaterial _importJwkEcPrivateKey(
  Map<String, dynamic> jwkData,
  EllipticCurve curve, {
  required String? expectedAlg,
  required String expectedUse,
}) {
  final jwk = JsonWebKey.fromJson(jwkData);
  _validateEcJwk(
    jwk,
    curve,
    isPrivateKey: true,
    expectedAlg: expectedAlg,
    expectedUse: expectedUse,
  );
  final point = _readEcJwkPoint(jwk, curve);
  final scalar = _readEcJwkCoordinate(jwk.d, 'd', curve);

  try {
    return jni.using((arena) {
      final parameters = _ecParameterSpec(arena, curve);
      final keyFactory = _ecKeyFactory(arena);
      final keySpec = ECPrivateKeySpec(_ecBigInteger(arena, scalar), parameters)
        ..releasedBy(arena);
      final key = keyFactory.generatePrivate(keySpec);
      if (key == null) {
        throw AssertionError('JCA EC KeyFactory returned a null private key');
      }

      return _validateEcKeyBeforeOwnershipTransfer(key, () {
        _validateEcPrivateKey(arena, key, curve);
        _validateEcPrivatePublicPair(arena, key, point, curve);
        return _EcPrivateKeyMaterial(_JcaKeyOwner(key), curve, point);
      });
    });
  } on jni.JThrowable catch (e) {
    throw _ecKeyFormatException(e, 'Unable to import EC private JWK');
  }
}

_EcPublicKeyMaterial _importJwkEcPublicKey(
  Map<String, dynamic> jwkData,
  EllipticCurve curve, {
  required String? expectedAlg,
  required String expectedUse,
}) {
  final jwk = JsonWebKey.fromJson(jwkData);
  _validateEcJwk(
    jwk,
    curve,
    isPrivateKey: false,
    expectedAlg: expectedAlg,
    expectedUse: expectedUse,
  );
  final point = _readEcJwkPoint(jwk, curve);

  try {
    return jni.using((arena) {
      final key = _ecPublicKeyFromPoint(arena, point, curve);
      return _validateEcKeyBeforeOwnershipTransfer(key, () {
        final actualPoint = _validateEcPublicKey(arena, key, curve);
        _checkData(
          _ecPointsEqual(point, actualPoint),
          'Invalid EC public key coordinates',
        );
        return _EcPublicKeyMaterial(_JcaKeyOwner(key), curve, actualPoint);
      });
    });
  } on jni.JThrowable catch (e) {
    throw _ecKeyFormatException(e, 'Unable to import EC public JWK');
  }
}

T _validateEcKeyBeforeOwnershipTransfer<T>(
  jni.JObject key,
  T Function() validate,
) {
  try {
    return validate();
  } catch (_) {
    key.release();
    rethrow;
  }
}

Uint8List _exportPkcs8EcPrivateKey(_EcPrivateKeyMaterial material) {
  try {
    return jni.using((arena) {
      final encoded = _copyEncodedEcKey(arena, material.owner.key, 'private');
      return _addPublicPointToEcPkcs8(encoded, material.publicPoint);
    });
  } on jni.JThrowable catch (e) {
    throw _ecOperationError(e, 'Unable to export PKCS#8 EC private key');
  }
}

Uint8List _exportSpkiEcPublicKey(_EcPublicKeyMaterial material) {
  try {
    return jni.using(
      (arena) => _copyEncodedEcKey(arena, material.owner.key, 'public'),
    );
  } on jni.JThrowable catch (e) {
    throw _ecOperationError(e, 'Unable to export SPKI EC public key');
  }
}

Uint8List _exportRawEcPublicKey(_EcPublicKeyMaterial material) {
  return _encodeRawEcPoint(material.point);
}

Map<String, dynamic> _exportJwkEcPrivateKey(
  _EcPrivateKeyMaterial material, {
  required String? jwkUse,
}) {
  try {
    return jni.using((arena) {
      final privateKey = material.owner.key.as(ECPrivateKey.type)
        ..releasedBy(arena);
      final scalar = privateKey.getS();
      if (scalar == null) {
        throw AssertionError('JCA EC private key has no scalar');
      }
      scalar.releasedBy(arena);

      return JsonWebKey(
        kty: 'EC',
        use: jwkUse,
        crv: material.curve._jwkCrv,
        x: _jwkEncodeBase64UrlNoPadding(material.publicPoint.x),
        y: _jwkEncodeBase64UrlNoPadding(material.publicPoint.y),
        d: _jwkEncodeBase64UrlNoPadding(
          _copyEcBigInteger(
            arena,
            scalar,
            material.curve._coordinateLength,
            'private scalar',
          ),
        ),
      ).toJson();
    });
  } on jni.JThrowable catch (e) {
    throw _ecOperationError(e, 'Unable to export EC private JWK');
  }
}

Map<String, dynamic> _exportJwkEcPublicKey(
  _EcPublicKeyMaterial material, {
  required String? jwkUse,
}) {
  return JsonWebKey(
    kty: 'EC',
    use: jwkUse,
    crv: material.curve._jwkCrv,
    x: _jwkEncodeBase64UrlNoPadding(material.point.x),
    y: _jwkEncodeBase64UrlNoPadding(material.point.y),
  ).toJson();
}

KeyFactory _ecKeyFactory(jni.Arena arena) {
  final algorithm = 'EC'.toJString()..releasedBy(arena);
  final keyFactory = KeyFactory.getInstance(algorithm);
  if (keyFactory == null) {
    throw AssertionError('JCA EC KeyFactory returned null');
  }
  keyFactory.releasedBy(arena);
  return keyFactory;
}

ECParameterSpec _ecParameterSpec(jni.Arena arena, EllipticCurve curve) {
  final parameters = _ecAlgorithmParameters(arena);
  final curveName = curve._jcaName.toJString()..releasedBy(arena);
  final namedCurve = ECGenParameterSpec(curveName)..releasedBy(arena);
  parameters.init(namedCurve);

  final parameterClass = ECParameterSpec.type.jClass..releasedBy(arena);
  final spec = parameters.getParameterSpec<ECParameterSpec>(parameterClass);
  if (spec == null) {
    throw AssertionError('JCA EC AlgorithmParameters returned null');
  }
  spec.releasedBy(arena);
  return spec;
}

AlgorithmParameters _ecAlgorithmParameters(jni.Arena arena) {
  final algorithm = 'EC'.toJString()..releasedBy(arena);
  final parameters = AlgorithmParameters.getInstance(algorithm);
  if (parameters == null) {
    throw AssertionError('JCA EC AlgorithmParameters returned null');
  }
  parameters.releasedBy(arena);
  return parameters;
}

jni.JObject _ecPublicKeyFromPoint(
  jni.Arena arena,
  _EcPointBytes point,
  EllipticCurve curve,
) {
  final parameters = _ecParameterSpec(arena, curve);
  final javaPoint = ECPoint(
    _ecBigInteger(arena, point.x),
    _ecBigInteger(arena, point.y),
  )..releasedBy(arena);
  final keySpec = ECPublicKeySpec(javaPoint, parameters)..releasedBy(arena);
  final key = _ecKeyFactory(arena).generatePublic(keySpec);
  if (key == null) {
    throw AssertionError('JCA EC KeyFactory returned a null public key');
  }
  return key;
}

void _validateEcPrivateKey(
  jni.Arena arena,
  jni.JObject key,
  EllipticCurve curve,
) {
  _checkData(
    key.isA(ECPrivateKey.type),
    'Invalid EC private key: EC parameters are required',
  );
  final privateKey = key.as(ECPrivateKey.type)..releasedBy(arena);
  _validateEcKeyCurve(arena, privateKey, curve);

  final scalar = privateKey.getS();
  _checkData(scalar != null, 'Invalid EC private key: scalar is missing');
  scalar!.releasedBy(arena);
  _checkData(
    scalar.signum() > 0,
    'Invalid EC private key: scalar must be positive',
  );

  final parameters = privateKey.getParams();
  _checkData(parameters != null, 'Invalid EC private key: parameters missing');
  parameters!.releasedBy(arena);
  final order = parameters.order;
  _checkData(order != null, 'Invalid EC private key: curve order is missing');
  order!.releasedBy(arena);
  _checkData(
    scalar.compareTo(order) < 0,
    'Invalid EC private key: scalar must be less than the curve order',
  );
}

_EcPointBytes _deriveEcPublicPoint(
  jni.Arena arena,
  jni.JObject privateKey,
  EllipticCurve curve,
) {
  final ecPrivateKey = privateKey.as(ECPrivateKey.type)..releasedBy(arena);
  final parameters = ecPrivateKey.getParams();
  if (parameters == null) {
    throw AssertionError('JCA EC private key has no parameters');
  }
  parameters.releasedBy(arena);

  final generator = parameters.generator;
  if (generator == null) {
    throw AssertionError('JCA EC parameters have no generator');
  }
  generator.releasedBy(arena);
  final generatorPoint = _copyEcPoint(arena, generator, curve);
  final generatorKey = _ecPublicKeyFromPoint(arena, generatorPoint, curve)
    ..releasedBy(arena);

  final algorithm = 'ECDH'.toJString()..releasedBy(arena);
  final agreement = KeyAgreement.getInstance(algorithm);
  if (agreement == null) {
    throw AssertionError('JCA ECDH KeyAgreement returned null');
  }
  agreement.releasedBy(arena);

  final jcaPrivateKey = privateKey.as(Key.type)..releasedBy(arena);
  final jcaGeneratorKey = generatorKey.as(Key.type)..releasedBy(arena);
  agreement.init(jcaPrivateKey);
  agreement.doPhase(jcaGeneratorKey, true)?.releasedBy(arena);
  final secret = agreement.generateSecret();
  if (secret == null) {
    throw AssertionError('JCA ECDH KeyAgreement returned no secret');
  }
  secret.releasedBy(arena);

  // ECDH with the curve generator computes d * G in provider code and returns
  // its affine x coordinate. Recovering y from the public x coordinate avoids
  // secret-dependent elliptic-curve arithmetic in Dart. All supported NIST
  // primes are 3 modulo 4, so each square root is y = rhs^((p + 1) / 4).
  final x = _normalizeEcCoordinate(secret.copyToDartBytes(), curve);
  final xValue = _readUnsignedBigInt(x);
  final curveParameters = curve._primeCurveParameters;
  final prime = curveParameters.prime;
  final rhs =
      (xValue.modPow(BigInt.from(3), prime) -
          BigInt.from(3) * xValue +
          curveParameters.b) %
      prime;
  final y = rhs.modPow((prime + BigInt.one) >> 2, prime);
  _checkData(
    y.modPow(BigInt.two, prime) == rhs,
    'Unable to derive the EC public point',
  );

  for (final yCandidate in <BigInt>[y, (prime - y) % prime]) {
    final point = (
      x: x,
      y: _writeFixedLengthUnsignedBigInt(yCandidate, curve._coordinateLength),
    );
    if (_ecPrivatePublicPairMatches(arena, privateKey, point, curve)) {
      return point;
    }
  }
  throw const FormatException('Unable to derive the EC public point');
}

Uint8List _normalizeEcCoordinate(Uint8List bytes, EllipticCurve curve) {
  if (bytes.isEmpty) {
    throw AssertionError('JCA ECDH returned an empty EC coordinate');
  }
  final length = curve._coordinateLength;
  var start = 0;
  while (bytes.length - start > length && bytes[start] == 0) {
    start++;
  }
  _checkData(
    bytes.length - start <= length,
    'JCA ECDH returned an oversized EC coordinate',
  );
  final result = Uint8List(length);
  result.setRange(length - (bytes.length - start), length, bytes, start);
  return result;
}

BigInt _readUnsignedBigInt(Uint8List bytes) {
  var result = BigInt.zero;
  for (final byte in bytes) {
    result = (result << 8) | BigInt.from(byte);
  }
  return result;
}

Uint8List _writeFixedLengthUnsignedBigInt(BigInt value, int length) {
  final result = Uint8List(length);
  var remaining = value;
  for (var i = result.length - 1; i >= 0 && remaining != BigInt.zero; i--) {
    result[i] = (remaining & BigInt.from(0xff)).toInt();
    remaining >>= 8;
  }
  _checkData(remaining == BigInt.zero, 'EC coordinate is too large');
  return result;
}

_EcPointBytes _validateEcPublicKey(
  jni.Arena arena,
  jni.JObject key,
  EllipticCurve curve,
) {
  _checkData(
    key.isA(ECPublicKey.type),
    'Invalid EC public key: EC parameters are required',
  );
  final publicKey = key.as(ECPublicKey.type)..releasedBy(arena);
  _validateEcKeyCurve(arena, publicKey, curve);

  final point = publicKey.getW();
  _checkData(point != null, 'Invalid EC public key: point is missing');
  point!.releasedBy(arena);
  return _copyEcPoint(arena, point, curve);
}

void _validateEcKeyCurve(jni.Arena arena, ECKey key, EllipticCurve curve) {
  final actualSpec = key.getParams();
  _checkData(
    actualSpec != null,
    'Invalid EC key: curve parameters are missing',
  );
  actualSpec!.releasedBy(arena);

  final actual = _encodeEcParameters(arena, actualSpec);
  final expected = _encodeEcParameters(arena, _ecParameterSpec(arena, curve));
  _checkData(
    _bytesEqual(actual, expected),
    'Invalid EC key: incorrect elliptic curve',
  );
}

Uint8List _encodeEcParameters(jni.Arena arena, ECParameterSpec parameters) {
  final algorithmParameters = _ecAlgorithmParameters(arena);
  algorithmParameters.init(parameters);
  final encoded = algorithmParameters.encoded;
  if (encoded == null) {
    throw AssertionError('JCA EC parameters have no encoded form');
  }
  encoded.releasedBy(arena);
  return encoded.copyToDartBytes();
}

void _validateEcPrivatePublicPair(
  jni.Arena arena,
  jni.JObject privateKey,
  _EcPointBytes publicPoint,
  EllipticCurve curve,
) {
  _checkData(
    _ecPrivatePublicPairMatches(arena, privateKey, publicPoint, curve),
    'Invalid EC private key: public point does not match private scalar',
  );
}

bool _ecPrivatePublicPairMatches(
  jni.Arena arena,
  jni.JObject privateKey,
  _EcPointBytes publicPoint,
  EllipticCurve curve,
) {
  final publicKey = _ecPublicKeyFromPoint(arena, publicPoint, curve)
    ..releasedBy(arena);
  final algorithm = 'SHA256withECDSA'.toJString()..releasedBy(arena);

  final signer = Signature.getInstance(algorithm);
  if (signer == null) {
    throw AssertionError('JCA ECDSA Signature returned null');
  }
  signer.releasedBy(arena);
  signer.initSign(privateKey);

  final validationData = arena.copyToJByteArray(Uint8List(1));
  signer.update$1(validationData);
  final signature = signer.sign();
  if (signature == null) {
    throw AssertionError('JCA ECDSA key validation returned null');
  }
  signature.releasedBy(arena);

  final verifier = Signature.getInstance(algorithm);
  if (verifier == null) {
    throw AssertionError('JCA ECDSA Signature returned null');
  }
  verifier.releasedBy(arena);
  verifier.initVerify(publicKey);
  verifier.update$1(validationData);
  return verifier.verify(signature);
}

Uint8List _copyEncodedEcKey(jni.Arena arena, jni.JObject key, String keyType) {
  final jcaKey = key.as(Key.type)..releasedBy(arena);
  final encoded = jcaKey.getEncoded();
  if (encoded == null) {
    throw AssertionError('JCA EC $keyType key has no encoded form');
  }
  encoded.releasedBy(arena);
  return encoded.copyToDartBytes();
}

BigInteger _ecBigInteger(jni.Arena arena, Uint8List unsignedBytes) {
  final bytes = arena.copyToJByteArray(unsignedBytes);
  return BigInteger.new$3(1, bytes)..releasedBy(arena);
}

_EcPointBytes _copyEcPoint(
  jni.Arena arena,
  ECPoint point,
  EllipticCurve curve,
) {
  final x = point.affineX;
  final y = point.affineY;
  _checkData(x != null && y != null, 'Invalid EC public key coordinates');
  x!.releasedBy(arena);
  y!.releasedBy(arena);
  return (
    x: _copyEcBigInteger(arena, x, curve._coordinateLength, 'x coordinate'),
    y: _copyEcBigInteger(arena, y, curve._coordinateLength, 'y coordinate'),
  );
}

Uint8List _copyEcBigInteger(
  jni.Arena arena,
  BigInteger value,
  int length,
  String name,
) {
  _checkData(value.signum() >= 0, 'Invalid EC key: $name must be non-negative');
  final encoded = value.toByteArray();
  if (encoded == null) {
    throw AssertionError(
      'JCA BigInteger.toByteArray() returned null for $name',
    );
  }
  encoded.releasedBy(arena);

  final signedBytes = encoded.copyToDartBytes();
  final start = signedBytes.length > 1 && signedBytes.first == 0 ? 1 : 0;
  final byteLength = signedBytes.length - start;
  _checkData(
    byteLength <= length,
    'Invalid EC key: $name exceeds $length bytes',
  );
  final result = Uint8List(length);
  result.setRange(length - byteLength, length, signedBytes, start);
  return result;
}

void _validateEcJwk(
  JsonWebKey jwk,
  EllipticCurve curve, {
  required bool isPrivateKey,
  required String? expectedAlg,
  required String expectedUse,
}) {
  void check(bool condition, String prop, String message) {
    _checkData(condition, 'JWK property "$prop" $message');
  }

  check(jwk.kty == 'EC', 'kty', 'must be "EC"');
  check(jwk.crv == curve._jwkCrv, 'crv', 'must be "${curve._jwkCrv}"');
  check(jwk.x != null, 'x', 'must be present');
  check(jwk.y != null, 'y', 'must be present');
  check(
    isPrivateKey ? jwk.d != null : jwk.d == null,
    'd',
    isPrivateKey
        ? 'must be present for a private key'
        : 'must not be present for a public key',
  );
  if (expectedAlg != null) {
    check(
      jwk.alg == null || jwk.alg == expectedAlg,
      'alg',
      'must be "$expectedAlg", if present',
    );
  }
  check(
    jwk.use == null || jwk.use == expectedUse,
    'use',
    'must be "$expectedUse", if present',
  );
}

_EcPointBytes _readEcJwkPoint(JsonWebKey jwk, EllipticCurve curve) {
  return (
    x: _readEcJwkCoordinate(jwk.x, 'x', curve),
    y: _readEcJwkCoordinate(jwk.y, 'y', curve),
  );
}

Uint8List _readEcJwkCoordinate(
  String? value,
  String prop,
  EllipticCurve curve,
) {
  _checkData(value != null, 'JWK property "$prop" must be present');
  final bytes = _jwkDecodeBase64UrlNoPadding(value!, prop);
  _checkData(
    bytes.length == curve._coordinateLength,
    'JWK property "$prop" must contain ${curve._coordinateLength} bytes',
  );
  return bytes;
}

_EcPointBytes _decodeRawEcPoint(Uint8List keyData, EllipticCurve curve) {
  final coordinateLength = curve._coordinateLength;
  _checkData(
    keyData.length == 1 + 2 * coordinateLength && keyData.first == 0x04,
    'Raw EC public key must be an uncompressed point',
  );
  return (
    x: Uint8List.fromList(
      Uint8List.sublistView(keyData, 1, 1 + coordinateLength),
    ),
    y: Uint8List.fromList(Uint8List.sublistView(keyData, 1 + coordinateLength)),
  );
}

Uint8List _encodeRawEcPoint(_EcPointBytes point) {
  return Uint8List.fromList(<int>[0x04, ...point.x, ...point.y]);
}

bool _ecPointsEqual(_EcPointBytes a, _EcPointBytes b) {
  return _bytesEqual(a.x, b.x) && _bytesEqual(a.y, b.y);
}

bool _bytesEqual(Uint8List a, Uint8List b) {
  if (a.length != b.length) {
    return false;
  }
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) {
      return false;
    }
  }
  return true;
}

void _validateEcDerSequence(Uint8List data, String name) {
  try {
    final reader = _DerReader(data);
    reader.readElement(0x30);
    reader.expectDone();
  } on FormatException catch (e) {
    throw FormatException('$name is not a complete DER sequence: ${e.message}');
  }
}

Uint8List _addPublicPointToEcPkcs8(
  Uint8List keyData,
  _EcPointBytes publicPoint,
) {
  try {
    final outerReader = _DerReader(keyData);
    final privateKeyInfo = _DerReader(outerReader.readElement(0x30));
    outerReader.expectDone();

    final version = privateKeyInfo.readEncodedElement(0x02);
    final algorithm = privateKeyInfo.readEncodedElement(0x30);
    final privateKey = privateKeyInfo.readElement(0x04);
    final trailingFields = <Uint8List>[];
    while (!privateKeyInfo.isDone) {
      trailingFields.add(privateKeyInfo.readAnyEncodedElement());
    }

    final ecPrivateKeyReader = _DerReader(privateKey);
    final ecPrivateKey = _DerReader(ecPrivateKeyReader.readElement(0x30));
    ecPrivateKeyReader.expectDone();

    final ecVersion = ecPrivateKey.readEncodedElement(0x02);
    final scalar = ecPrivateKey.readEncodedElement(0x04);
    final optionalFields = <Uint8List>[];
    while (!ecPrivateKey.isDone) {
      final tag = ecPrivateKey.peekTag;
      final field = ecPrivateKey.readAnyEncodedElement();
      if (tag != 0xa1) {
        optionalFields.add(field);
      }
    }

    final publicKey = _encodeDerElement(
      0xa1,
      _encodeDerElement(
        0x03,
        Uint8List.fromList(<int>[0, ..._encodeRawEcPoint(publicPoint)]),
      ),
    );
    final ecPrivateKeyWithPublicPoint = _encodeDerElement(
      0x30,
      Uint8List.fromList(<int>[
        ...ecVersion,
        ...scalar,
        for (final field in optionalFields) ...field,
        ...publicKey,
      ]),
    );
    return _encodeDerElement(
      0x30,
      Uint8List.fromList(<int>[
        ...version,
        ...algorithm,
        ..._encodeDerElement(0x04, ecPrivateKeyWithPublicPoint),
        for (final field in trailingFields) ...field,
      ]),
    );
  } on FormatException catch (e) {
    throw operationError('JCA EC private key has invalid PKCS#8 encoding: $e');
  }
}

_EcPointBytes? _extractEcPublicPointFromPkcs8(
  Uint8List keyData,
  EllipticCurve curve,
) {
  try {
    final outerReader = _DerReader(keyData);
    final privateKeyInfo = _DerReader(outerReader.readElement(0x30));
    outerReader.expectDone();

    privateKeyInfo.readElement(0x02);
    privateKeyInfo.readElement(0x30);
    final privateKey = privateKeyInfo.readElement(0x04);

    final ecPrivateKeyReader = _DerReader(privateKey);
    final ecPrivateKey = _DerReader(ecPrivateKeyReader.readElement(0x30));
    ecPrivateKeyReader.expectDone();
    ecPrivateKey.readElement(0x02);
    ecPrivateKey.readElement(0x04);

    while (!ecPrivateKey.isDone) {
      final tag = ecPrivateKey.peekTag;
      if (tag == 0xa0) {
        ecPrivateKey.readElement(0xa0);
        continue;
      }
      if (tag == 0xa1) {
        final publicKey = _DerReader(ecPrivateKey.readElement(0xa1));
        final point = _readEcPointBitString(publicKey.readElement(0x03), curve);
        publicKey.expectDone();
        return point;
      }
      throw const FormatException('unexpected ECPrivateKey field');
    }

    while (!privateKeyInfo.isDone) {
      final tag = privateKeyInfo.peekTag;
      if (tag == 0xa0) {
        privateKeyInfo.readElement(0xa0);
        continue;
      }
      if (tag == 0x81) {
        return _readEcPointBitString(privateKeyInfo.readElement(0x81), curve);
      }
      privateKeyInfo.readElement(tag);
    }
    return null;
  } on FormatException {
    return null;
  }
}

Uint8List _encodeDerElement(int tag, Uint8List value) {
  return Uint8List.fromList(<int>[
    tag,
    ..._encodeDerLength(value.length),
    ...value,
  ]);
}

List<int> _encodeDerLength(int length) {
  if (length < 0x80) {
    return <int>[length];
  }
  if (length <= 0xff) {
    return <int>[0x81, length];
  }
  return <int>[0x82, length >> 8, length & 0xff];
}

_EcPointBytes _readEcPointBitString(Uint8List bitString, EllipticCurve curve) {
  _checkData(
    bitString.isNotEmpty && bitString.first == 0,
    'EC public point bit string must have no unused bits',
  );
  return _decodeRawEcPoint(Uint8List.sublistView(bitString, 1), curve);
}

FormatException _ecKeyFormatException(
  jni.JThrowable throwable,
  String context,
) {
  return FormatException('$context: ${_ecThrowableMessage(throwable)}');
}

OperationError _ecOperationError(jni.JThrowable throwable, String context) {
  return operationError('$context: ${_ecThrowableMessage(throwable)}');
}

String _ecThrowableMessage(jni.JThrowable throwable) {
  late final String message;
  try {
    message = throwable.message;
  } finally {
    throwable.release();
  }
  return message;
}

final class _DerReader {
  _DerReader(this._data);

  final Uint8List _data;
  var _offset = 0;

  bool get isDone => _offset == _data.length;

  int get peekTag {
    if (isDone) {
      throw const FormatException('unexpected end of DER data');
    }
    return _data[_offset];
  }

  Uint8List readElement(int expectedTag) {
    if (peekTag != expectedTag) {
      throw FormatException(
        'expected DER tag 0x${expectedTag.toRadixString(16)}',
      );
    }
    _offset++;
    final length = _readLength();
    if (length > _data.length - _offset) {
      throw const FormatException('truncated DER element');
    }
    final value = Uint8List.sublistView(_data, _offset, _offset + length);
    _offset += length;
    return value;
  }

  Uint8List readEncodedElement(int expectedTag) {
    final start = _offset;
    readElement(expectedTag);
    return Uint8List.sublistView(_data, start, _offset);
  }

  Uint8List readAnyEncodedElement() {
    return readEncodedElement(peekTag);
  }

  void expectDone() {
    if (!isDone) {
      throw const FormatException('trailing DER data');
    }
  }

  int _readLength() {
    if (_offset >= _data.length) {
      throw const FormatException('missing DER length');
    }
    final first = _data[_offset++];
    if (first < 0x80) {
      return first;
    }

    final byteCount = first & 0x7f;
    if (byteCount == 0 || byteCount > 4 || byteCount > _data.length - _offset) {
      throw const FormatException('invalid DER length');
    }
    if (_data[_offset] == 0) {
      throw const FormatException('non-minimal DER length');
    }

    var length = 0;
    for (var i = 0; i < byteCount; i++) {
      length = (length << 8) | _data[_offset++];
    }
    if (length < 0x80) {
      throw const FormatException('non-minimal DER length');
    }
    return length;
  }
}
