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

part of impl_ffi;

Future<EcdhPrivateKey> ecdhPrivateKey_importPkcs8Key(
  List<int> keyData,
  EllipticCurve curve,
) async =>
    _EcdhPrivateKey(_importPkcs8EcPrivateKey(keyData, curve));

Future<EcdhPrivateKey> ecdhPrivateKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  EllipticCurve curve,
) async =>
    _EcdhPrivateKey(_importJwkEcPrivateOrPublicKey(
      JsonWebKey.fromJson(jwk),
      curve,
      isPrivateKey: true,
      expectedUse: 'enc',
      expectedAlg: null, // ECDH has no validation of 'jwk.alg'
    ));

Future<KeyPair<EcdhPrivateKey, EcdhPublicKey>> ecdhPrivateKey_generateKey(
  EllipticCurve curve,
) async {
  final p = _generateEcKeyPair(curve);
  return _KeyPair(
    privateKey: _EcdhPrivateKey(p.privateKey),
    publicKey: _EcdhPublicKey(p.publicKey),
  );
}

Future<EcdhPublicKey> ecdhPublicKey_importRawKey(
  List<int> keyData,
  EllipticCurve curve,
) async =>
    _EcdhPublicKey(_importRawEcPublicKey(keyData, curve));

Future<EcdhPublicKey> ecdhPublicKey_importSpkiKey(
  List<int> keyData,
  EllipticCurve curve,
) async =>
    _EcdhPublicKey(_importSpkiEcPublicKey(keyData, curve));

Future<EcdhPublicKey> ecdhPublicKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  EllipticCurve curve,
) async =>
    _EcdhPublicKey(_importJwkEcPrivateOrPublicKey(
      JsonWebKey.fromJson(jwk),
      curve,
      isPrivateKey: false,
      expectedUse: 'enc',
      expectedAlg: null, // ECDH has no validation of 'jwk.alg'
    ));

class _EcdhPrivateKey implements EcdhPrivateKey {
  final _EvpPKey _key;

  _EcdhPrivateKey(this._key);

  @override
  Future<Uint8List> deriveBits(int length, EcdhPublicKey publicKey) async {
    ArgumentError.checkNotNull(length, 'length');
    ArgumentError.checkNotNull(publicKey, 'publicKey');
    if (publicKey is! _EcdhPublicKey) {
      throw ArgumentError.value(
        publicKey,
        'publicKey',
        'custom implementations of EcdhPublicKey is not supported',
      );
    }
    if (length <= 0) {
      throw ArgumentError.value(length, 'length', 'must be positive');
    }

    final scope = _Scope();
    try {
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
        throw _OperationError(
          'Length in ECDH key derivation is too large. '
          'Maximum allowed is $maxLength bits.',
        );
      }

      if (length == 0) {
        return Uint8List.fromList([]);
      }

      final lengthInBytes = (length / 8).ceil();
      final derived = _withOutPointer(lengthInBytes, (ffi.Pointer<ffi.Void> p) {
        final outLen = ssl.ECDH_compute_key(
          p,
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
      });

      // Only return the first [length] bits from derived.
      final zeroBits = lengthInBytes * 8 - length;
      assert(zeroBits < 8);
      if (zeroBits > 0) {
        derived.last &= ((0xff << zeroBits) & 0xff);
      }

      return derived;
    } finally {
      scope.release();
    }
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async =>
      // Neither Chrome or Firefox produces 'use': 'enc' for ECDH, we choose to
      // omit it for better interoperability. Chrome incorrectly forbids during
      // import (though we strip 'use' to mitigate this).
      // See also: https://crbug.com/641499 (and importJsonWebKey in JS)
      _exportJwkEcPrivateOrPublicKey(_key, isPrivateKey: true, jwkUse: null);

  @override
  Future<Uint8List> exportPkcs8Key() async {
    return _withOutCBB((cbb) {
      _checkOp(ssl.EVP_marshal_private_key.invoke(cbb, _key) == 1);
    });
  }
}

class _EcdhPublicKey implements EcdhPublicKey {
  final _EvpPKey _key;

  _EcdhPublicKey(this._key);

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
  Future<Uint8List> exportSpkiKey() async {
    return _withOutCBB((cbb) {
      _checkOp(ssl.EVP_marshal_public_key.invoke(cbb, _key) == 1);
    });
  }
}
