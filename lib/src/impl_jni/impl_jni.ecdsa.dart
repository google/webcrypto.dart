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

part of 'impl_jni.dart';

final class _StaticEcdsaPrivateKeyImpl implements StaticEcdsaPrivateKeyImpl {
  const _StaticEcdsaPrivateKeyImpl();

  @override
  Future<EcdsaPrivateKeyImpl> importPkcs8Key(
    List<int> keyData,
    EllipticCurve curve,
  ) async {
    return _EcdsaPrivateKeyImpl(
      _importPkcs8EcPrivateKey(_asUint8List(keyData), curve),
    );
  }

  @override
  Future<EcdsaPrivateKeyImpl> importJsonWebKey(
    Map<String, dynamic> jwk,
    EllipticCurve curve,
  ) async {
    return _EcdsaPrivateKeyImpl(
      _importJwkEcPrivateKey(
        jwk,
        curve,
        expectedAlg: curve._ecdsaJwkAlg,
        expectedUse: 'sig',
      ),
    );
  }

  @override
  Future<(EcdsaPrivateKeyImpl, EcdsaPublicKeyImpl)> generateKey(
    EllipticCurve curve,
  ) async {
    final keyPair = await _generateEcKeyPair(curve);
    final publicKey = _importSpkiEcPublicKey(keyPair.publicKeyData, curve);
    final privateKey = _importPkcs8EcPrivateKey(
      keyPair.privateKeyData,
      curve,
      publicPoint: publicKey.point,
    );
    return (_EcdsaPrivateKeyImpl(privateKey), _EcdsaPublicKeyImpl(publicKey));
  }
}

final class _EcdsaPrivateKeyImpl implements EcdsaPrivateKeyImpl {
  _EcdsaPrivateKeyImpl(this._key);

  final _EcPrivateKeyMaterial _key;

  @override
  Future<Uint8List> signBytes(List<int> data, HashImpl hash) {
    return signStream(Stream.value(data), hash);
  }

  @override
  Future<Uint8List> signStream(Stream<List<int>> data, HashImpl hash) {
    return _signEcdsaStream(_key, _ecHashFromHash(hash), data);
  }

  @override
  Future<Uint8List> exportPkcs8Key() async => _exportPkcs8EcPrivateKey(_key);

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async =>
      _exportJwkEcPrivateKey(_key, jwkUse: 'sig');
}

final class _StaticEcdsaPublicKeyImpl implements StaticEcdsaPublicKeyImpl {
  const _StaticEcdsaPublicKeyImpl();

  @override
  Future<EcdsaPublicKeyImpl> importRawKey(
    List<int> keyData,
    EllipticCurve curve,
  ) async {
    return _EcdsaPublicKeyImpl(
      _importRawEcPublicKey(_asUint8List(keyData), curve),
    );
  }

  @override
  Future<EcdsaPublicKeyImpl> importJsonWebKey(
    Map<String, dynamic> jwk,
    EllipticCurve curve,
  ) async {
    return _EcdsaPublicKeyImpl(
      _importJwkEcPublicKey(
        jwk,
        curve,
        expectedAlg: curve._ecdsaJwkAlg,
        expectedUse: 'sig',
      ),
    );
  }

  @override
  Future<EcdsaPublicKeyImpl> importSpkiKey(
    List<int> keyData,
    EllipticCurve curve,
  ) async {
    return _EcdsaPublicKeyImpl(
      _importSpkiEcPublicKey(_asUint8List(keyData), curve),
    );
  }
}

final class _EcdsaPublicKeyImpl implements EcdsaPublicKeyImpl {
  _EcdsaPublicKeyImpl(this._key);

  final _EcPublicKeyMaterial _key;

  @override
  Future<bool> verifyBytes(List<int> signature, List<int> data, HashImpl hash) {
    return verifyStream(signature, Stream.value(data), hash);
  }

  @override
  Future<bool> verifyStream(
    List<int> signature,
    Stream<List<int>> data,
    HashImpl hash,
  ) {
    return _verifyEcdsaStream(
      _key,
      _ecHashFromHash(hash),
      _asUint8List(signature),
      data,
    );
  }

  @override
  Future<Uint8List> exportRawKey() async => _exportRawEcPublicKey(_key);

  @override
  Future<Uint8List> exportSpkiKey() async => _exportSpkiEcPublicKey(_key);

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async =>
      _exportJwkEcPublicKey(_key, jwkUse: 'sig');
}

Future<Uint8List> _signEcdsaStream(
  _EcPrivateKeyMaterial key,
  _HashImpl hash,
  Stream<List<int>> data,
) async {
  final arena = jni.Arena();
  try {
    final signature = _createEcdsaSignature(arena, hash);
    signature.initSign(key.owner.key);

    final buffer = jni.JByteArray(_defaultChunkSize)..releasedBy(arena);
    await for (final chunk in data) {
      _updateEcdsaSignature(signature, buffer, chunk);
    }

    final derSignature = signature.sign();
    if (derSignature == null) {
      throw AssertionError('JCA ECDSA returned null');
    }
    derSignature.releasedBy(arena);
    return _ecdsaDerToRaw(
      derSignature.copyToDartBytes(),
      key.curve._coordinateLength,
    );
  } on jni.JThrowable catch (e) {
    throw _ecOperationError(e, 'JCA ECDSA signing failed');
  } finally {
    arena.releaseAll();
  }
}

Future<bool> _verifyEcdsaStream(
  _EcPublicKeyMaterial key,
  _HashImpl hash,
  Uint8List rawSignature,
  Stream<List<int>> data,
) async {
  final derSignature = _ecdsaRawToDer(
    rawSignature,
    key.curve._coordinateLength,
  );
  if (derSignature == null) {
    return false;
  }

  final arena = jni.Arena();
  try {
    final verifier = _createEcdsaSignature(arena, hash);
    verifier.initVerify(key.owner.key);

    final buffer = jni.JByteArray(_defaultChunkSize)..releasedBy(arena);
    await for (final chunk in data) {
      _updateEcdsaSignature(verifier, buffer, chunk);
    }

    final javaSignature = arena.copyToJByteArray(derSignature);
    try {
      return verifier.verify(javaSignature);
    } on jni.JThrowable catch (e) {
      e.release();
      return false;
    }
  } on jni.JThrowable catch (e) {
    throw _ecOperationError(e, 'JCA ECDSA verification failed');
  } finally {
    arena.releaseAll();
  }
}

Signature _createEcdsaSignature(jni.Arena arena, _HashImpl hash) {
  final name = hash._ecdsaJcaName;
  final algorithm = name.toJString()..releasedBy(arena);
  final signature = Signature.getInstance(algorithm);
  if (signature == null) {
    throw AssertionError('JCA Signature($name) returned null');
  }
  signature.releasedBy(arena);
  return signature;
}

void _updateEcdsaSignature(
  Signature signature,
  jni.JByteArray buffer,
  List<int> chunk,
) {
  final bytes = _asUint8List(chunk);
  var offset = 0;
  while (offset < bytes.length) {
    final length = math.min(bytes.length - offset, _defaultChunkSize);
    buffer.setRange(0, length, bytes, offset);
    signature.update$2(buffer, 0, length);
    offset += length;
  }
}

_HashImpl _ecHashFromHash(HashImpl hash) {
  if (hash is _HashImpl) {
    return hash;
  }
  throw AssertionError('Custom implementations of HashImpl are not supported.');
}

extension _EcdsaHashMetadata on _HashImpl {
  String get _ecdsaJcaName {
    return switch (_jcaName) {
      'SHA-1' => 'SHA1withECDSA',
      'SHA-256' => 'SHA256withECDSA',
      'SHA-384' => 'SHA384withECDSA',
      'SHA-512' => 'SHA512withECDSA',
      _ => throw AssertionError('Unknown hash algorithm: $_jcaName'),
    };
  }
}

extension _EcdsaCurveMetadata on EllipticCurve {
  String get _ecdsaJwkAlg {
    return switch (this) {
      EllipticCurve.p256 => 'ES256',
      EllipticCurve.p384 => 'ES384',
      EllipticCurve.p521 => 'ES512',
    };
  }
}

Uint8List _ecdsaDerToRaw(Uint8List signature, int coordinateLength) {
  try {
    final outer = _DerReader(signature);
    final sequence = _DerReader(outer.readElement(0x30));
    outer.expectDone();
    final r = _readEcdsaDerInteger(sequence, coordinateLength);
    final s = _readEcdsaDerInteger(sequence, coordinateLength);
    sequence.expectDone();
    return Uint8List.fromList(<int>[...r, ...s]);
  } on FormatException catch (e) {
    throw operationError('JCA ECDSA returned an invalid DER signature: $e');
  }
}

Uint8List? _ecdsaRawToDer(Uint8List signature, int coordinateLength) {
  if (signature.length != 2 * coordinateLength) {
    return null;
  }
  final r = Uint8List.sublistView(signature, 0, coordinateLength);
  final s = Uint8List.sublistView(signature, coordinateLength);
  final body = Uint8List.fromList(<int>[
    ..._encodeEcdsaDerInteger(r),
    ..._encodeEcdsaDerInteger(s),
  ]);
  return Uint8List.fromList(<int>[
    0x30,
    ..._encodeDerLength(body.length),
    ...body,
  ]);
}

Uint8List _readEcdsaDerInteger(_DerReader reader, int coordinateLength) {
  final encoded = reader.readElement(0x02);
  if (encoded.isEmpty || encoded.first & 0x80 != 0) {
    throw const FormatException('ECDSA INTEGER must be positive');
  }
  if (encoded.length > 1 && encoded.first == 0 && encoded[1] & 0x80 == 0) {
    throw const FormatException('ECDSA INTEGER has unnecessary leading zero');
  }

  final start = encoded.length > 1 && encoded.first == 0 ? 1 : 0;
  final length = encoded.length - start;
  if (length > coordinateLength) {
    throw const FormatException('ECDSA INTEGER exceeds curve size');
  }
  final result = Uint8List(coordinateLength);
  result.setRange(coordinateLength - length, coordinateLength, encoded, start);
  return result;
}

Uint8List _encodeEcdsaDerInteger(Uint8List value) {
  var start = 0;
  while (start < value.length - 1 && value[start] == 0) {
    start++;
  }
  final needsSignPadding = value[start] & 0x80 != 0;
  final length = value.length - start + (needsSignPadding ? 1 : 0);
  return Uint8List.fromList(<int>[
    0x02,
    ..._encodeDerLength(length),
    if (needsSignPadding) 0,
    ...Uint8List.sublistView(value, start),
  ]);
}
