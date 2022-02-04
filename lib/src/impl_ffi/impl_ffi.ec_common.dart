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

/// Get `ssl.NID_...` from BoringSSL matching the given [curve].
int _ecCurveToNID(EllipticCurve curve) {
  ArgumentError.checkNotNull(curve, 'curve');

  if (curve == EllipticCurve.p256) {
    return NID_X9_62_prime256v1;
  }
  if (curve == EllipticCurve.p384) {
    return NID_secp384r1;
  }
  if (curve == EllipticCurve.p521) {
    return NID_secp521r1;
  }
  // This should never happen!
  throw UnsupportedError('curve "$curve" is not supported');
}

/// Get [EllipticCurve] from matching BoringSSL `ssl.NID_...`.
EllipticCurve _ecCurveFromNID(int nid) {
  if (nid == NID_X9_62_prime256v1) {
    return EllipticCurve.p256;
  }
  if (nid == NID_secp384r1) {
    return EllipticCurve.p384;
  }
  if (nid == NID_secp521r1) {
    return EllipticCurve.p521;
  }
  // This should never happen!
  throw _OperationError('internal error detecting curve');
}

String _ecCurveToJwkCrv(EllipticCurve curve) {
  ArgumentError.checkNotNull(curve, 'curve');

  if (curve == EllipticCurve.p256) {
    return 'P-256';
  }
  if (curve == EllipticCurve.p384) {
    return 'P-384';
  }
  if (curve == EllipticCurve.p521) {
    return 'P-521';
  }
  // This should never happen!
  throw UnsupportedError('curve "$curve" is not supported');
}

/// Perform some post-import validation for EC keys.
void _validateEllipticCurveKey(
  _EvpPKey key,
  EllipticCurve curve,
) {
  final scope = _Scope();
  try {
    _checkData(ssl.EVP_PKEY_id.invoke(key) == EVP_PKEY_EC,
        message: 'key is not an EC key');

    final ec = ssl.EVP_PKEY_get1_EC_KEY.invoke(key);
    _checkData(ec.address != 0, fallback: 'key is not an EC key');
    scope.defer(() => ssl.EC_KEY_free(ec));

    _checkDataIsOne(ssl.EC_KEY_check_key(ec), fallback: 'invalid key');

    // When importing BoringSSL will compute the public key if omitted, and
    // leave a flag, such that exporting the private key won't include the
    // public key.
    final encFlags = ssl.EC_KEY_get_enc_flags(ec);
    ssl.EC_KEY_set_enc_flags(ec, encFlags & ~EC_PKEY_NO_PUBKEY);

    // Check the curve of the imported key
    final nid = ssl.EC_GROUP_get_curve_name(ssl.EC_KEY_get0_group(ec));
    _checkData(_ecCurveToNID(curve) == nid,
        message: 'incorrect elliptic curve');
  } finally {
    scope.release();
  }
}

_EvpPKey _importPkcs8EcPrivateKey(
  List<int> keyData,
  EllipticCurve curve,
) {
  final k = _withDataAsCBS(keyData, ssl.EVP_parse_private_key);
  _checkData(k.address != 0, fallback: 'unable to parse key');
  final key = _EvpPKey.wrap(k);

  _validateEllipticCurveKey(key, curve);
  return key;
}

_EvpPKey _importSpkiEcPublicKey(
  List<int> keyData,
  EllipticCurve curve,
) {
  // TODO: When calling EVP_parse_public_key it might wise to check that CBS_len(cbs) == 0 is true afterwards
  // otherwise it might be that all of the contents of the key was not consumed and we should throw
  // a FormatException. Notice that this the case for private/public keys, and RSA keys.
  final k = _withDataAsCBS(keyData, ssl.EVP_parse_public_key);
  _checkData(k.address != 0, fallback: 'unable to parse key');
  final key = _EvpPKey.wrap(k);

  _validateEllipticCurveKey(key, curve);

  return key;
}

_EvpPKey _importJwkEcPrivateOrPublicKey(
  JsonWebKey jwk,
  EllipticCurve curve, {
  required bool isPrivateKey,
  required String expectedUse,
  String? expectedAlg, // may be null, if 'alg' property isn't validated (ECDH)
}) {
  _checkData(
    jwk.kty == 'EC',
    message: 'expected a elliptic-curve key, JWK property "kty" must be "EC"',
  );
  _checkData(
    jwk.x != null,
    message: 'expected a elliptic-curve key, JWK property "x" to be present',
  );
  _checkData(
    jwk.y != null,
    message: 'expected a elliptic-curve key, JWK property "y" to be present',
  );
  if (isPrivateKey) {
    _checkData(
      jwk.d != null,
      message: 'expected a private key, JWK property "d" is missing',
    );
  } else {
    _checkData(
      jwk.d == null,
      message: 'expected a public key, JWK property "d" is present',
    );
  }

  final crv = _ecCurveToJwkCrv(curve);
  _checkData(jwk.crv == crv, message: 'JWK property "crv" is not "$crv"');

  _checkData(expectedAlg == null || jwk.alg == null || jwk.alg == expectedAlg,
      message: 'JWK property "alg" should be "$expectedAlg", if present');

  _checkData(jwk.use == null || jwk.use == expectedUse,
      message: 'JWK property "use" should be "$expectedUse", if present');

  // TODO: Reject keys with key_ops in inconsistent with isPrivateKey
  //       Also in the js implementation...

  final scope = _Scope();
  try {
    final ec = ssl.EC_KEY_new_by_curve_name(_ecCurveToNID(curve));
    _checkOp(ec.address != 0, fallback: 'internal failure to use curve');
    scope.defer(() => ssl.EC_KEY_free(ec));

    // We expect parameters to have this size
    final paramSize = _numBitsToBytes(ssl.EC_GROUP_get_degree(
      ssl.EC_KEY_get0_group(ec),
    ));

    // Utility to decode a JWK parameter.
    ffi.Pointer<BIGNUM> decodeParam(String val, String prop) {
      final bytes = _jwkDecodeBase64UrlNoPadding(val, prop);
      _checkData(
        bytes.length == paramSize,
        message: 'JWK property "$prop" should hold $paramSize bytes',
      );
      final bn = ssl.BN_bin2bn(
        scope.dataAsPointer(bytes),
        bytes.length,
        ffi.nullptr,
      );
      _checkData(bn.address != 0);
      scope.defer(() => ssl.BN_free(bn));
      return bn;
    }

    // Note: ideally we wouldn't throw data errors in case of internal errors
    _checkDataIsOne(
      ssl.EC_KEY_set_public_key_affine_coordinates(
        ec,
        decodeParam(jwk.x!, 'x'),
        decodeParam(jwk.y!, 'y'),
      ),
      fallback: 'invalid EC key',
    );

    if (isPrivateKey) {
      _checkDataIsOne(
        ssl.EC_KEY_set_private_key(ec, decodeParam(jwk.d!, 'd')),
        fallback: 'invalid EC key',
      );
    }

    _checkDataIsOne(ssl.EC_KEY_check_key(ec), fallback: 'invalid EC key');

    // Wrap with an EVP_KEY
    final key = _EvpPKey();
    _checkOpIsOne(ssl.EVP_PKEY_set1_EC_KEY.invoke(key, ec));

    return key;
  } finally {
    scope.release();
  }
}

_EvpPKey _importRawEcPublicKey(
  List<int> keyData,
  EllipticCurve curve,
) {
  // See: https://chromium.googlesource.com/chromium/src/+/43d62c50b705f88c67b14539e91fd8fd017f70c4/components/webcrypto/algorithms/ec.cc#332

  // Create EC_KEY for the curve
  final ec = ssl.EC_KEY_new_by_curve_name(_ecCurveToNID(curve));
  _checkOp(ec.address != 0, fallback: 'internal failure to use curve');

  try {
    // Create EC_POINT to hold public key info
    final pub = ssl.EC_POINT_new(ssl.EC_KEY_get0_group(ec));
    _checkOp(pub.address != 0, fallback: 'internal point allocation error');
    try {
      // Read raw public key
      _withDataAsPointer(keyData, (ffi.Pointer<ffi.Uint8> p) {
        _checkDataIsOne(
          ssl.EC_POINT_oct2point(
              ssl.EC_KEY_get0_group(ec), pub, p, keyData.length, ffi.nullptr),
          fallback: 'invalid keyData',
        );
      });
      // Copy pub point to ec
      _checkDataIsOne(ssl.EC_KEY_set_public_key(ec, pub),
          fallback: 'invalid keyData');

      final key = _EvpPKey();
      _checkOpIsOne(ssl.EVP_PKEY_set1_EC_KEY.invoke(key, ec));
      _validateEllipticCurveKey(key, curve);

      return key;
    } finally {
      ssl.EC_POINT_free(pub);
    }
  } finally {
    ssl.EC_KEY_free(ec);
  }
}

Uint8List _exportRawEcPublicKey(_EvpPKey key) {
  final scope = _Scope();
  try {
    final ec = ssl.EVP_PKEY_get1_EC_KEY.invoke(key);
    _checkOp(ec.address != 0, fallback: 'internal key type invariant error');
    scope.defer(() => ssl.EC_KEY_free(ec));

    return _withOutCBB((cbb) {
      return _checkOpIsOne(
          ssl.EC_POINT_point2cbb(
            cbb,
            ssl.EC_KEY_get0_group(ec),
            ssl.EC_KEY_get0_public_key(ec),
            point_conversion_form_t.POINT_CONVERSION_UNCOMPRESSED,
            ffi.nullptr,
          ),
          fallback: 'formatting failed');
    });
  } finally {
    scope.release();
  }
}

Map<String, dynamic> _exportJwkEcPrivateOrPublicKey(
  _EvpPKey key, {
  required bool isPrivateKey,
  String? jwkUse,
}) {
  final scope = _Scope();
  try {
    final ec = ssl.EVP_PKEY_get1_EC_KEY.invoke(key);
    _checkOp(ec.address != 0, fallback: 'internal key type invariant error');
    scope.defer(() => ssl.EC_KEY_free(ec));

    final group = ssl.EC_KEY_get0_group(ec);
    final curve = _ecCurveFromNID(ssl.EC_GROUP_get_curve_name(group));

    // Determine byte size used for encoding params
    final paramSize = _numBitsToBytes(ssl.EC_GROUP_get_degree(group));

    final x = scope.create(ssl.BN_new, ssl.BN_free);
    final y = scope.create(ssl.BN_new, ssl.BN_free);

    _checkOpIsOne(ssl.EC_POINT_get_affine_coordinates_GFp(
      group,
      ssl.EC_KEY_get0_public_key(ec),
      x,
      y,
      ffi.nullptr,
    ));

    final xAsBytes = _withOutPointer(paramSize, (ffi.Pointer<ffi.Uint8> p) {
      _checkOpIsOne(ssl.BN_bn2bin_padded(p, paramSize, x));
    });
    final yAsBytes = _withOutPointer(paramSize, (ffi.Pointer<ffi.Uint8> p) {
      _checkOpIsOne(ssl.BN_bn2bin_padded(p, paramSize, y));
    });

    Uint8List? dAsBytes;
    if (isPrivateKey) {
      final d = ssl.EC_KEY_get0_private_key(ec);
      dAsBytes = _withOutPointer(paramSize, (ffi.Pointer<ffi.Uint8> p) {
        _checkOpIsOne(ssl.BN_bn2bin_padded(p, paramSize, d));
      });
    }

    return JsonWebKey(
      kty: 'EC',
      use: jwkUse,
      crv: _ecCurveToJwkCrv(curve),
      x: _jwkEncodeBase64UrlNoPadding(xAsBytes),
      y: _jwkEncodeBase64UrlNoPadding(yAsBytes),
      d: dAsBytes != null ? _jwkEncodeBase64UrlNoPadding(dAsBytes) : null,
    ).toJson();
  } finally {
    scope.release();
  }
}

KeyPair<_EvpPKey, _EvpPKey> _generateEcKeyPair(
  EllipticCurve curve,
) {
  final scope = _Scope();
  try {
    final ecPriv = ssl.EC_KEY_new_by_curve_name(_ecCurveToNID(curve));
    _checkOp(ecPriv.address != 0, fallback: 'internal failure to use curve');
    scope.defer(() => ssl.EC_KEY_free(ecPriv));

    _checkOpIsOne(ssl.EC_KEY_generate_key(ecPriv));

    final privKey = _EvpPKey();
    _checkOpIsOne(ssl.EVP_PKEY_set1_EC_KEY.invoke(privKey, ecPriv));

    final ecPub = ssl.EC_KEY_new_by_curve_name(_ecCurveToNID(curve));
    _checkOp(ecPub.address != 0);
    scope.defer(() => ssl.EC_KEY_free(ecPub));
    _checkOpIsOne(ssl.EC_KEY_set_public_key(
      ecPub,
      ssl.EC_KEY_get0_public_key(ecPriv),
    ));

    final pubKey = _EvpPKey();
    _checkOpIsOne(ssl.EVP_PKEY_set1_EC_KEY.invoke(pubKey, ecPub));

    return _KeyPair(
      privateKey: privKey,
      publicKey: pubKey,
    );
  } finally {
    scope.release();
  }
}
