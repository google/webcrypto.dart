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

final class _StaticEcdhPrivateKeyImpl implements StaticEcdhPrivateKeyImpl {
  const _StaticEcdhPrivateKeyImpl();

  @override
  Future<EcdhPrivateKeyImpl> importPkcs8Key(
    List<int> keyData,
    EllipticCurve curve,
  ) async {
    return _EcdhPrivateKeyImpl(
      _importPkcs8EcPrivateKey(_asUint8List(keyData), curve),
    );
  }

  @override
  Future<EcdhPrivateKeyImpl> importJsonWebKey(
    Map<String, dynamic> jwk,
    EllipticCurve curve,
  ) async {
    return _EcdhPrivateKeyImpl(
      _importJwkEcPrivateKey(
        jwk,
        curve,
        // ECDH has no algorithm-specific JWK `alg` value to validate.
        expectedAlg: null,
        expectedUse: 'enc',
      ),
    );
  }

  @override
  Future<(EcdhPrivateKeyImpl, EcdhPublicKeyImpl)> generateKey(
    EllipticCurve curve,
  ) async {
    final keyPair = await _generateEcKeyPair(curve);
    final publicKey = _importSpkiEcPublicKey(keyPair.publicKeyData, curve);
    final privateKey = _importPkcs8EcPrivateKey(
      keyPair.privateKeyData,
      curve,
      publicPoint: publicKey.point,
    );
    return (_EcdhPrivateKeyImpl(privateKey), _EcdhPublicKeyImpl(publicKey));
  }
}

final class _EcdhPrivateKeyImpl implements EcdhPrivateKeyImpl {
  _EcdhPrivateKeyImpl(this._key);

  final _EcPrivateKeyMaterial _key;

  @override
  Future<Uint8List> deriveBits(int length, EcdhPublicKeyImpl publicKey) async {
    if (publicKey is! _EcdhPublicKeyImpl) {
      throw ArgumentError.value(
        publicKey,
        'publicKey',
        'custom implementations of EcdhPublicKey are not supported',
      );
    }
    if (length < 0) {
      throw ArgumentError.value(length, 'length', 'must be non-negative');
    }
    if (_key.curve != publicKey._key.curve) {
      throw ArgumentError.value(
        publicKey,
        'publicKey',
        'Public and private key for ECDH key derivation have the same '
            'elliptic curve',
      );
    }

    final maxLength = _key.curve._coordinateLength * 8;
    if (length > maxLength) {
      throw operationError(
        'Length in ECDH key derivation is too large. '
        'Maximum allowed is $maxLength bits.',
      );
    }
    if (length == 0) {
      return Uint8List(0);
    }

    final lengthInBytes = (length + 7) ~/ 8;
    try {
      return jni.using((arena) {
        final algorithm = 'ECDH'.toJString()..releasedBy(arena);
        final agreement = KeyAgreement.getInstance(algorithm);
        if (agreement == null) {
          throw AssertionError('JCA ECDH KeyAgreement returned null');
        }
        agreement.releasedBy(arena);

        final privateKey = _key.owner.key.as(Key.type)..releasedBy(arena);
        final peerPublicKey = publicKey._key.owner.key.as(Key.type)
          ..releasedBy(arena);
        agreement.init(privateKey);
        agreement.doPhase(peerPublicKey, true)?.releasedBy(arena);

        final secret = agreement.generateSecret();
        if (secret == null) {
          throw AssertionError('JCA ECDH KeyAgreement returned no secret');
        }
        secret.releasedBy(arena);

        final fullSecret = _normalizeEcCoordinate(
          secret.copyToDartBytes(),
          _key.curve,
        );
        final result = Uint8List.fromList(
          Uint8List.sublistView(fullSecret, 0, lengthInBytes),
        );

        // WebCrypto returns the leftmost requested bits. Keep the final byte
        // deterministic when the requested length is not byte-aligned.
        final zeroBits = lengthInBytes * 8 - length;
        if (zeroBits > 0) {
          result.last &= (0xff << zeroBits) & 0xff;
        }
        return result;
      });
    } on jni.JThrowable catch (e) {
      throw _ecOperationError(e, 'JCA ECDH key derivation failed');
    }
  }

  @override
  Future<Uint8List> exportPkcs8Key() async => _exportPkcs8EcPrivateKey(_key);

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async =>
      _exportJwkEcPrivateKey(_key, jwkUse: null);
}

final class _StaticEcdhPublicKeyImpl implements StaticEcdhPublicKeyImpl {
  const _StaticEcdhPublicKeyImpl();

  @override
  Future<EcdhPublicKeyImpl> importRawKey(
    List<int> keyData,
    EllipticCurve curve,
  ) async {
    return _EcdhPublicKeyImpl(
      _importRawEcPublicKey(_asUint8List(keyData), curve),
    );
  }

  @override
  Future<EcdhPublicKeyImpl> importSpkiKey(
    List<int> keyData,
    EllipticCurve curve,
  ) async {
    return _EcdhPublicKeyImpl(
      _importSpkiEcPublicKey(_asUint8List(keyData), curve),
    );
  }

  @override
  Future<EcdhPublicKeyImpl> importJsonWebKey(
    Map<String, dynamic> jwk,
    EllipticCurve curve,
  ) async {
    return _EcdhPublicKeyImpl(
      _importJwkEcPublicKey(
        jwk,
        curve,
        // ECDH has no algorithm-specific JWK `alg` value to validate.
        expectedAlg: null,
        expectedUse: 'enc',
      ),
    );
  }
}

final class _EcdhPublicKeyImpl implements EcdhPublicKeyImpl {
  _EcdhPublicKeyImpl(this._key);

  final _EcPublicKeyMaterial _key;

  @override
  Future<Uint8List> exportRawKey() async => _exportRawEcPublicKey(_key);

  @override
  Future<Uint8List> exportSpkiKey() async => _exportSpkiEcPublicKey(_key);

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async =>
      _exportJwkEcPublicKey(_key, jwkUse: null);
}
