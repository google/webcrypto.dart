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

Future<EcdhPrivateKeyImpl> ecdhPrivateKey_importPkcs8Key(
  List<int> keyData,
  EllipticCurve curve,
) async =>
    _EcdhPrivateKeyImpl(_importPkcs8EcPrivateKey(keyData, curve));

Future<EcdhPrivateKeyImpl> ecdhPrivateKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  EllipticCurve curve,
) async =>
    _EcdhPrivateKeyImpl(_importJwkEcPrivateOrPublicKey(
      JsonWebKey.fromJson(jwk),
      curve,
      isPrivateKey: true,
      expectedUse: 'enc',
      expectedAlg: null, // ECDH has no validation of 'jwk.alg'
    ));

Future<KeyPair<EcdhPrivateKeyImpl, EcdhPublicKeyImpl>>
    ecdhPrivateKey_generateKey(
  EllipticCurve curve,
) async {
  final p = _generateEcKeyPair(curve);
  return (
    privateKey: _EcdhPrivateKeyImpl(p.privateKey),
    publicKey: _EcdhPublicKeyImpl(p.publicKey),
  );
}

Future<EcdhPublicKeyImpl> ecdhPublicKey_importRawKey(
  List<int> keyData,
  EllipticCurve curve,
) async =>
    _EcdhPublicKeyImpl(_importRawEcPublicKey(keyData, curve));

Future<EcdhPublicKeyImpl> ecdhPublicKey_importSpkiKey(
  List<int> keyData,
  EllipticCurve curve,
) async =>
    _EcdhPublicKeyImpl(_importSpkiEcPublicKey(keyData, curve));

Future<EcdhPublicKeyImpl> ecdhPublicKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  EllipticCurve curve,
) async =>
    _EcdhPublicKeyImpl(_importJwkEcPrivateOrPublicKey(
      JsonWebKey.fromJson(jwk),
      curve,
      isPrivateKey: false,
      expectedUse: 'enc',
      expectedAlg: null, // ECDH has no validation of 'jwk.alg'
    ));

final class _StaticEcdhPrivateKeyImpl implements StaticEcdhPrivateKeyImpl {
  const _StaticEcdhPrivateKeyImpl();

  @override
  Future<EcdhPrivateKeyImpl> importPkcs8Key(
          List<int> keyData, EllipticCurve curve) =>
      ecdhPrivateKey_importPkcs8Key(keyData, curve);

  @override
  Future<EcdhPrivateKeyImpl> importJsonWebKey(
          Map<String, dynamic> jwk, EllipticCurve curve) =>
      ecdhPrivateKey_importJsonWebKey(jwk, curve);

  @override
  Future<(EcdhPrivateKeyImpl, EcdhPublicKeyImpl)> generateKey(
      EllipticCurve curve) async {
    final KeyPair<EcdhPrivateKeyImpl, EcdhPublicKeyImpl> keyPair =
        await ecdhPrivateKey_generateKey(curve);

    return (keyPair.privateKey, keyPair.publicKey);
  }
}

final class _EcdhPrivateKeyImpl implements EcdhPrivateKeyImpl {
  final _EvpPKey _key;

  _EcdhPrivateKeyImpl(this._key);

  @override
  String toString() {
    return 'Instance of \'EcdhPrivateKey\'';
  }

  @override
  Future<Uint8List> deriveBits(int length, EcdhPublicKeyImpl publicKey) async {
    if (publicKey is! _EcdhPublicKeyImpl) {
      throw ArgumentError.value(
        publicKey,
        'publicKey',
        'custom implementations of EcdhPublicKey is not supported',
      );
    }
    if (length <= 0) {
      throw ArgumentError.value(length, 'length', 'must be positive');
    }

    return _Scope.async((scope) async {
      final pubEcKey = ssl.EVP_PKEY_get1_EC_KEY.invoke(publicKey._key);
      _checkOp(pubEcKey.address != 0, fallback: 'not an ec key');
      scope.defer(() => ssl.EC_KEY_free(pubEcKey));

      final privEcKey = ssl.EVP_PKEY_get1_EC_KEY.invoke(_key);
      _checkOp(privEcKey.address != 0, fallback: 'not an ec key');
      scope.defer(() => ssl.EC_KEY_free(privEcKey));

      // Check that public/private key uses the same elliptic curve.
      if (ssl.EC_GROUP_get_curve_name(ssl.EC_KEY_get0_group(pubEcKey)) !=
          ssl.EC_GROUP_get_curve_name(ssl.EC_KEY_get0_group(privEcKey))) {
        // Note: web crypto will throw an InvalidAccessError here.
        throw ArgumentError.value(
          publicKey,
          'publicKey',
          'Public and private key for ECDH key derivation have the same '
              'elliptic curve',
        );
      }

      // Field size rounded up to 8 bits is the maximum number of bits we can
      // derive. The most significant bits will be zero in this case.
      final fieldSize =
          ssl.EC_GROUP_get_degree(ssl.EC_KEY_get0_group(privEcKey));
      final maxLength = 8 * (fieldSize / 8).ceil();
      if (length > maxLength) {
        throw operationError(
          'Length in ECDH key derivation is too large. '
          'Maximum allowed is $maxLength bits.',
        );
      }

      if (length == 0) {
        return Uint8List.fromList(const []);
      }

      final lengthInBytes = (length / 8).ceil();
      final out = scope<ffi.Uint8>(lengthInBytes);
      final outLen = ssl.ECDH_compute_key(
        out.cast(),
        lengthInBytes,
        ssl.EC_KEY_get0_public_key(pubEcKey),
        privEcKey,
        ffi.nullptr,
      );
      _checkOp(outLen != -1, fallback: 'ECDH key derivation failed');
      _checkOp(
        outLen == lengthInBytes,
        message: 'internal error in ECDH key derivation',
      );
      final derived = out.copy(lengthInBytes);

      // Only return the first [length] bits from derived.
      final zeroBits = lengthInBytes * 8 - length;
      assert(zeroBits < 8);
      if (zeroBits > 0) {
        derived.last &= ((0xff << zeroBits) & 0xff);
      }

      return derived;
    });
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async =>
      // Neither Chrome or Firefox produces 'use': 'enc' for ECDH, we choose to
      // omit it for better interoperability. Chrome incorrectly forbids during
      // import (though we strip 'use' to mitigate this).
      // See also: https://crbug.com/641499 (and importJsonWebKey in JS)
      _exportJwkEcPrivateOrPublicKey(_key, isPrivateKey: true, jwkUse: null);

  @override
  Future<Uint8List> exportPkcs8Key() async => _exportPkcs8Key(_key);
}

final class _StaticEcdhPublicKeyImpl implements StaticEcdhPublicKeyImpl {
  const _StaticEcdhPublicKeyImpl();

  @override
  Future<EcdhPublicKeyImpl> importRawKey(
          List<int> keyData, EllipticCurve curve) =>
      ecdhPublicKey_importRawKey(keyData, curve);

  @override
  Future<EcdhPublicKeyImpl> importSpkiKey(
          List<int> keyData, EllipticCurve curve) =>
      ecdhPublicKey_importSpkiKey(keyData, curve);

  @override
  Future<EcdhPublicKeyImpl> importJsonWebKey(
          Map<String, dynamic> jwk, EllipticCurve curve) =>
      ecdhPublicKey_importJsonWebKey(jwk, curve);
}

final class _EcdhPublicKeyImpl implements EcdhPublicKeyImpl {
  final _EvpPKey _key;

  _EcdhPublicKeyImpl(this._key);

  @override
  String toString() {
    return 'Instance of \'EcdhPublicKey\'';
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async =>
      // Neither Chrome or Firefox produces 'use': 'enc' for ECDH, we choose to
      // omit it for better interoperability. Chrome incorrectly forbids during
      // import (though we strip 'use' to mitigate this).
      // See also: https://crbug.com/641499 (and importJsonWebKey in JS)
      _exportJwkEcPrivateOrPublicKey(_key, isPrivateKey: false, jwkUse: null);

  @override
  Future<Uint8List> exportRawKey() async => _exportRawEcPublicKey(_key);

  @override
  Future<Uint8List> exportSpkiKey() async => _exportSpkiKey(_key);
}
