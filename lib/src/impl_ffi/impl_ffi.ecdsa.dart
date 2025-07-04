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

/// Get valid value for `jwk.alg` property given an [EllipticCurve] for ECDSA.
String _ecdsaCurveToJwkAlg(EllipticCurve curve) {
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

Future<EcdsaPrivateKeyImpl> ecdsaPrivateKey_importPkcs8Key(
  List<int> keyData,
  EllipticCurve curve,
) async =>
    _EcdsaPrivateKeyImpl(_importPkcs8EcPrivateKey(keyData, curve));

Future<EcdsaPrivateKeyImpl> ecdsaPrivateKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  EllipticCurve curve,
) async =>
    _EcdsaPrivateKeyImpl(_importJwkEcPrivateOrPublicKey(
      JsonWebKey.fromJson(jwk),
      curve,
      isPrivateKey: true,
      expectedUse: 'sig',
      expectedAlg: _ecdsaCurveToJwkAlg(curve),
    ));

Future<KeyPair<EcdsaPrivateKeyImpl, EcdsaPublicKeyImpl>>
    ecdsaPrivateKey_generateKey(
  EllipticCurve curve,
) async {
  final p = _generateEcKeyPair(curve);
  return (
    privateKey: _EcdsaPrivateKeyImpl(p.privateKey),
    publicKey: _EcdsaPublicKeyImpl(p.publicKey),
  );
}

Future<EcdsaPublicKeyImpl> ecdsaPublicKey_importRawKey(
  List<int> keyData,
  EllipticCurve curve,
) async =>
    _EcdsaPublicKeyImpl(_importRawEcPublicKey(keyData, curve));

Future<EcdsaPublicKeyImpl> ecdsaPublicKey_importSpkiKey(
  List<int> keyData,
  EllipticCurve curve,
) async =>
    _EcdsaPublicKeyImpl(_importSpkiEcPublicKey(keyData, curve));

Future<EcdsaPublicKeyImpl> ecdsaPublicKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  EllipticCurve curve,
) async =>
    _EcdsaPublicKeyImpl(_importJwkEcPrivateOrPublicKey(
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
  return _Scope.sync((scope) {
    // TODO: Check if cbs is empty after parsing, consider using ECDSA_SIG_from_bytes instead (like chrome does)
    final ecdsa = ssl.ECDSA_SIG_parse(scope.createCBS(signature));
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

    // Access R and S from the ecdsa signature
    final R = scope<ffi.Pointer<BIGNUM>>();
    final S = scope<ffi.Pointer<BIGNUM>>();
    ssl.ECDSA_SIG_get0(ecdsa, R, S);

    // Dump R and S to return value.
    final out = scope<ffi.Uint8>(N * 2);
    _checkOpIsOne(
      ssl.BN_bn2bin_padded(out + 0, N, R.value),
      fallback: 'internal error formatting R in signature',
    );
    _checkOpIsOne(
      ssl.BN_bn2bin_padded(out + N, N, S.value),
      fallback: 'internal error formatting S in signature',
    );
    return out.copy(N * 2);
  });
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
  return _Scope.sync((scope) {
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

    final ecdsa = scope.create(ssl.ECDSA_SIG_new, ssl.ECDSA_SIG_free);

    // Access R and S from the ecdsa signature
    final R = scope<ffi.Pointer<BIGNUM>>();
    final S = scope<ffi.Pointer<BIGNUM>>();
    ssl.ECDSA_SIG_get0(ecdsa, R, S);

    final psig = scope.dataAsPointer<ffi.Uint8>(signature);
    _checkOp(
      ssl.BN_bin2bn(psig + 0, N, R.value).address != 0,
      fallback: 'allocation failure',
    );
    _checkOp(
      ssl.BN_bin2bn(psig + N, N, S.value).address != 0,
      fallback: 'allocation failure',
    );

    final cbb = scope.createCBB();
    _checkOpIsOne(
      ssl.ECDSA_SIG_marshal(cbb, ecdsa),
      fallback: 'internal error reformatting signature',
    );
    return cbb.copy();
  });
}

final class _StaticEcdsaPrivateKeyImpl implements StaticEcdsaPrivateKeyImpl {
  const _StaticEcdsaPrivateKeyImpl();

  @override
  Future<EcdsaPrivateKeyImpl> importPkcs8Key(
          List<int> keyData, EllipticCurve curve) =>
      ecdsaPrivateKey_importPkcs8Key(keyData, curve);

  @override
  Future<EcdsaPrivateKeyImpl> importJsonWebKey(
    Map<String, dynamic> jwk,
    EllipticCurve curve,
  ) =>
      ecdsaPrivateKey_importJsonWebKey(jwk, curve);

  @override
  Future<(EcdsaPrivateKeyImpl, EcdsaPublicKeyImpl)> generateKey(
    EllipticCurve curve,
  ) async {
    final KeyPair<EcdsaPrivateKeyImpl, EcdsaPublicKeyImpl> keyPair =
        await ecdsaPrivateKey_generateKey(curve);

    return (keyPair.privateKey, keyPair.publicKey);
  }
}

final class _EcdsaPrivateKeyImpl implements EcdsaPrivateKeyImpl {
  final _EvpPKey _key;

  _EcdsaPrivateKeyImpl(this._key);

  @override
  String toString() {
    return 'Instance of \'EcdsaPrivateKeyImpl\'';
  }

  @override
  Future<Uint8List> signBytes(List<int> data, HashImpl hash) =>
      signStream(Stream.value(data), hash);

  @override
  Future<Uint8List> signStream(Stream<List<int>> data, HashImpl hash) async {
    final md = _HashImpl.fromHash(hash)._md;
    final sig = await _signStream(_key, md, data);
    return _convertEcdsaDerSignatureToWebCryptoSignature(_key, sig);
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async =>
      _exportJwkEcPrivateOrPublicKey(_key, isPrivateKey: true, jwkUse: 'sig');

  @override
  Future<Uint8List> exportPkcs8Key() async => _exportPkcs8Key(_key);
}

final class _StaticEcdsaPublicKeyImpl implements StaticEcdsaPublicKeyImpl {
  const _StaticEcdsaPublicKeyImpl();

  @override
  Future<EcdsaPublicKeyImpl> importRawKey(
          List<int> keyData, EllipticCurve curve) =>
      ecdsaPublicKey_importRawKey(keyData, curve);

  @override
  Future<EcdsaPublicKeyImpl> importJsonWebKey(
    Map<String, dynamic> jwk,
    EllipticCurve curve,
  ) =>
      ecdsaPublicKey_importJsonWebKey(jwk, curve);

  @override
  Future<EcdsaPublicKeyImpl> importSpkiKey(
          List<int> keyData, EllipticCurve curve) =>
      ecdsaPublicKey_importSpkiKey(keyData, curve);
}

final class _EcdsaPublicKeyImpl implements EcdsaPublicKeyImpl {
  final _EvpPKey _key;

  _EcdsaPublicKeyImpl(this._key);

  @override
  String toString() {
    return 'Instance of \'EcdsaPublicKeyImpl\'';
  }

  @override
  Future<bool> verifyBytes(
          List<int> signature, List<int> data, HashImpl hash) =>
      verifyStream(signature, Stream.value(data), hash);

  @override
  Future<bool> verifyStream(
    List<int> signature,
    Stream<List<int>> data,
    HashImpl hash,
  ) async {
    final md = _HashImpl.fromHash(hash)._md;

    // Convert to DER signature
    final sig = _convertEcdsaWebCryptoSignatureToDerSignature(_key, signature);
    if (sig == null) {
      // If signature format is invalid we fail verification
      return false;
    }

    return await _verifyStream(_key, md, sig, data);
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async =>
      _exportJwkEcPrivateOrPublicKey(_key, isPrivateKey: false, jwkUse: 'sig');

  @override
  Future<Uint8List> exportRawKey() async => _exportRawEcPublicKey(_key);

  @override
  Future<Uint8List> exportSpkiKey() async => _exportSpkiKey(_key);
}
