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

/// Get valid value for `jwk.alg` property given an [EllipticCurve] for ECDSA.
String _ecdsaCurveToJwkAlg(EllipticCurve curve) {
  ArgumentError.checkNotNull(curve, 'curve');

  if (curve == EllipticCurve.p256) {
    return 'ES256';
  }
  if (curve == EllipticCurve.p384) {
    return 'ES384';
  }
  if (curve == EllipticCurve.p521) {
    // ES512 means P-521 with SHA-512 (not a typo)
    return 'ES512';
  }
  // This should never happen!
  throw UnsupportedError('curve "$curve" is not supported');
}

Future<EcdsaPrivateKey> ecdsaPrivateKey_importPkcs8Key(
  List<int> keyData,
  EllipticCurve curve,
) async =>
    _EcdsaPrivateKey(_importPkcs8EcPrivateKey(keyData, curve));

Future<EcdsaPrivateKey> ecdsaPrivateKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  EllipticCurve curve,
) async =>
    _EcdsaPrivateKey(_importJwkEcPrivateOrPublicKey(
      JsonWebKey.fromJson(jwk),
      curve,
      isPrivateKey: true,
      expectedUse: 'sig',
      expectedAlg: _ecdsaCurveToJwkAlg(curve),
    ));

Future<KeyPair<EcdsaPrivateKey, EcdsaPublicKey>> ecdsaPrivateKey_generateKey(
  EllipticCurve curve,
) async {
  final p = _generateEcKeyPair(curve);
  return _KeyPair(
    privateKey: _EcdsaPrivateKey(p.privateKey),
    publicKey: _EcdsaPublicKey(p.publicKey),
  );
}

Future<EcdsaPublicKey> ecdsaPublicKey_importRawKey(
  List<int> keyData,
  EllipticCurve curve,
) async =>
    _EcdsaPublicKey(_importRawEcPublicKey(keyData, curve));

Future<EcdsaPublicKey> ecdsaPublicKey_importSpkiKey(
  List<int> keyData,
  EllipticCurve curve,
) async =>
    _EcdsaPublicKey(_importSpkiEcPublicKey(keyData, curve));

Future<EcdsaPublicKey> ecdsaPublicKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  EllipticCurve curve,
) async =>
    _EcdsaPublicKey(_importJwkEcPrivateOrPublicKey(
      JsonWebKey.fromJson(jwk),
      curve,
      isPrivateKey: false,
      expectedUse: 'sig',
      expectedAlg: _ecdsaCurveToJwkAlg(curve),
    ));

/// Convert ECDSA signature in DER format returned by BoringSSL to the raw R + S
/// formated specified in the webcrypto specification.
///
/// See also: https://chromium.googlesource.com/chromium/src/+/43d62c50b705f88c67b14539e91fd8fd017f70c4/components/webcrypto/algorithms/ecdsa.cc#69
Uint8List _convertEcdsaDerSignatureToWebCryptoSignature(
  _EvpPKey key,
  Uint8List signature,
) {
  final scope = _Scope();
  try {
    final ecdsa = _withDataAsCBS(signature, ssl.ECDSA_SIG_parse);
    _checkOp(ecdsa.address != 0,
        message: 'internal error formatting signature');
    scope.defer(() => ssl.ECDSA_SIG_free(ecdsa));

    // Read EC key and get the number of bytes required to encode R and S.
    final ec = ssl.EVP_PKEY_get1_EC_KEY.invoke(key);
    _checkOp(ec.address != 0, message: 'internal key type invariant violation');
    scope.defer(() => ssl.EC_KEY_free(ec));

    final N = ssl.BN_num_bytes(ssl.EC_GROUP_get0_order(ssl.EC_KEY_get0_group(
      ec,
    )));

    return _withAllocation(_sslAlloc<ffi.Pointer<BIGNUM>>(2),
        (ffi.Pointer<ffi.Pointer<BIGNUM>> RS) {
      // Access R and S from the ecdsa signature
      final R = RS.elementAt(0);
      final S = RS.elementAt(1);
      ssl.ECDSA_SIG_get0(ecdsa, R, S);

      // Dump R and S to return value.
      return _withOutPointer(N * 2, (ffi.Pointer<ffi.Uint8> p) {
        _checkOpIsOne(
          ssl.BN_bn2bin_padded(p.elementAt(0), N, R.value),
          fallback: 'internal error formatting R in signature',
        );
        _checkOpIsOne(
          ssl.BN_bn2bin_padded(p.elementAt(N), N, S.value),
          fallback: 'internal error formatting S in signature',
        );
      });
    });
  } finally {
    scope.release();
  }
}

/// Convert ECDSA signature in the raw R + S as specified in webcrypto to DER
/// format as expected by BoringSSL.
///
/// Returns `null` if the [signature] is invalid and should be rejected.
///
/// See also: https://chromium.googlesource.com/chromium/src/+/43d62c50b705f88c67b14539e91fd8fd017f70c4/components/webcrypto/algorithms/ecdsa.cc#111
Uint8List? _convertEcdsaWebCryptoSignatureToDerSignature(
  _EvpPKey key,
  List<int> signature,
) {
  final scope = _Scope();
  try {
    // Read EC key and get the number of bytes required to encode R and S.
    final ec = ssl.EVP_PKEY_get1_EC_KEY.invoke(key);
    _checkOp(ec.address != 0, message: 'internal key type invariant violation');
    scope.defer(() => ssl.EC_KEY_free(ec));

    final N = ssl.BN_num_bytes(ssl.EC_GROUP_get0_order(ssl.EC_KEY_get0_group(
      ec,
    )));

    if (N * 2 != signature.length) {
      // If the signature format is invalid we consider the signature invalid and
      // return false from verification method. This follows:
      // https://chromium.googlesource.com/chromium/src/+/43d62c50b705f88c67b14539e91fd8fd017f70c4/components/webcrypto/algorithms/ecdsa.cc#111
      return null;
    }

    final ecdsa = ssl.ECDSA_SIG_new();
    _checkOp(ecdsa.address != 0,
        message: 'internal error formatting signature');
    scope.defer(() => ssl.ECDSA_SIG_free(ecdsa));

    return _withAllocation(_sslAlloc<ffi.Pointer<BIGNUM>>(2),
        (ffi.Pointer<ffi.Pointer<BIGNUM>> RS) {
      // Access R and S from the ecdsa signature
      final R = RS.elementAt(0);
      final S = RS.elementAt(1);
      ssl.ECDSA_SIG_get0(ecdsa, R, S);

      _withDataAsPointer(signature, (ffi.Pointer<ffi.Uint8> p) {
        _checkOp(
          ssl.BN_bin2bn(p.elementAt(0), N, R.value).address != 0,
          fallback: 'allocation failure',
        );
        _checkOp(
          ssl.BN_bin2bn(p.elementAt(N), N, S.value).address != 0,
          fallback: 'allocation failure',
        );
      });
      return _withOutCBB((cbb) => _checkOpIsOne(
            ssl.ECDSA_SIG_marshal(cbb, ecdsa),
            fallback: 'internal error reformatting signature',
          ));
    });
  } finally {
    scope.release();
  }
}

class _EcdsaPrivateKey implements EcdsaPrivateKey {
  final _EvpPKey _key;

  _EcdsaPrivateKey(this._key);

  @override
  Future<Uint8List> signBytes(List<int> data, Hash hash) {
    ArgumentError.checkNotNull(data, 'data');
    ArgumentError.checkNotNull(hash, 'hash');
    return signStream(Stream.value(data), hash);
  }

  @override
  Future<Uint8List> signStream(Stream<List<int>> data, Hash hash) async {
    ArgumentError.checkNotNull(data, 'data');
    ArgumentError.checkNotNull(hash, 'hash');
    final _hash = _Hash.fromHash(hash).MD;

    final sig = await _withEVP_MD_CTX((ctx) async {
      _checkOpIsOne(ssl.EVP_DigestSignInit.invoke(
        ctx,
        ffi.nullptr,
        _hash,
        ffi.nullptr,
        _key,
      ));

      await _streamToUpdate(data, ctx, ssl.EVP_DigestSignUpdate);
      return _withAllocation(_sslAlloc<ffi.IntPtr>(),
          (ffi.Pointer<ffi.IntPtr> len) {
        len.value = 0;
        _checkOpIsOne(ssl.EVP_DigestSignFinal(ctx, ffi.nullptr, len));
        return _withOutPointer(len.value, (ffi.Pointer<ffi.Uint8> p) {
          _checkOpIsOne(ssl.EVP_DigestSignFinal(ctx, p, len));
        }).sublist(0, len.value);
      });
    });
    return _convertEcdsaDerSignatureToWebCryptoSignature(_key, sig);
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async =>
      _exportJwkEcPrivateOrPublicKey(_key, isPrivateKey: true, jwkUse: 'sig');

  @override
  Future<Uint8List> exportPkcs8Key() async {
    return _withOutCBB((cbb) {
      _checkOp(ssl.EVP_marshal_private_key.invoke(cbb, _key) == 1);
    });
  }
}

class _EcdsaPublicKey implements EcdsaPublicKey {
  final _EvpPKey _key;

  _EcdsaPublicKey(this._key);

  @override
  Future<bool> verifyBytes(List<int> signature, List<int> data, Hash hash) {
    ArgumentError.checkNotNull(signature, 'signature');
    ArgumentError.checkNotNull(data, 'data');
    ArgumentError.checkNotNull(hash, 'hash');
    return verifyStream(signature, Stream.value(data), hash);
  }

  @override
  Future<bool> verifyStream(
    List<int> signature,
    Stream<List<int>> data,
    Hash hash,
  ) async {
    ArgumentError.checkNotNull(signature, 'signature');
    ArgumentError.checkNotNull(data, 'data');
    ArgumentError.checkNotNull(hash, 'hash');
    final _hash = _Hash.fromHash(hash).MD;

    // Convert to DER signature
    final sig = _convertEcdsaWebCryptoSignatureToDerSignature(_key, signature);
    if (sig == null) {
      // If signature format is invalid we fail verification
      return false;
    }

    return await _withEVP_MD_CTX((ctx) async {
      return await _withPEVP_PKEY_CTX((pctx) async {
        _checkOpIsOne(ssl.EVP_DigestVerifyInit.invoke(
          ctx,
          pctx,
          _hash,
          ffi.nullptr,
          _key,
        ));
        await _streamToUpdate(data, ctx, ssl.EVP_DigestVerifyUpdate);
        return _withDataAsPointer(sig, (ffi.Pointer<ffi.Uint8> p) {
          final result = ssl.EVP_DigestVerifyFinal(ctx, p, sig.length);
          if (result != 1) {
            // TODO: We should always clear errors, when returning from any
            //       function that uses BoringSSL.
            // Note: In this case we could probably assert that error is just
            //       signature related.
            ssl.ERR_clear_error();
          }
          return result == 1;
        });
      });
    });
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async =>
      _exportJwkEcPrivateOrPublicKey(_key, isPrivateKey: false, jwkUse: 'sig');

  @override
  Future<Uint8List> exportRawKey() async => _exportRawEcPublicKey(_key);

  @override
  Future<Uint8List> exportSpkiKey() async {
    return _withOutCBB((cbb) {
      _checkOp(ssl.EVP_marshal_public_key.invoke(cbb, _key) == 1);
    });
  }
}
