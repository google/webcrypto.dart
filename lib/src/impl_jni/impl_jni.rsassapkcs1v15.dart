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

final class _StaticRsaSsaPkcs1V15PrivateKeyImpl
    implements StaticRsaSsaPkcs1v15PrivateKeyImpl {
  const _StaticRsaSsaPkcs1V15PrivateKeyImpl();

  @override
  Future<RsaSsaPkcs1V15PrivateKeyImpl> importPkcs8Key(
    List<int> keyData,
    HashImpl hash,
  ) async {
    final h = _rsaHashFromHash(hash);
    return _RsaSsaPkcs1V15PrivateKeyImpl(
      _importPkcs8RsaPrivateKey(_asUint8List(keyData)),
      h,
    );
  }

  @override
  Future<RsaSsaPkcs1V15PrivateKeyImpl> importJsonWebKey(
    Map<String, dynamic> jwk,
    HashImpl hash,
  ) async {
    final h = _rsaHashFromHash(hash);
    return _RsaSsaPkcs1V15PrivateKeyImpl(
      _importJwkRsaPrivateKey(
        jwk,
        expectedAlg: h._rsassaPkcs1v15JwkAlg,
        expectedUse: 'sig',
      ),
      h,
    );
  }

  @override
  Future<(RsaSsaPkcs1V15PrivateKeyImpl, RsaSsaPkcs1V15PublicKeyImpl)>
  generateKey(int modulusLength, BigInt publicExponent, HashImpl hash) async {
    final h = _rsaHashFromHash(hash);
    final keyPair = await _generateRsaKeyPair(modulusLength, publicExponent);
    return (
      _RsaSsaPkcs1V15PrivateKeyImpl(keyPair.privateKeyData, h),
      _RsaSsaPkcs1V15PublicKeyImpl(keyPair.publicKeyData, h),
    );
  }
}

final class _RsaSsaPkcs1V15PrivateKeyImpl
    implements RsaSsaPkcs1V15PrivateKeyImpl {
  _RsaSsaPkcs1V15PrivateKeyImpl(Uint8List keyData, this._hash)
    : _keyData = Uint8List.fromList(keyData);

  final Uint8List _keyData;
  final _HashImpl _hash;

  @override
  Future<Uint8List> signBytes(List<int> data) => signStream(Stream.value(data));

  @override
  Future<Uint8List> signStream(Stream<List<int>> data) async {
    final arena = jni.Arena();
    try {
      final key = _rsaPrivateKeyFromPkcs8(arena, _keyData);
      final signature = _createRsaSsaPkcs1V15Signature(arena, _hash);
      signature.initSign(key);

      final buffer = jni.JByteArray(_defaultChunkSize)..releasedBy(arena);
      await for (final chunk in data) {
        _updateRsaSignature(signature, buffer, chunk);
      }

      final result = signature.sign();
      if (result == null) {
        throw AssertionError('JCA RSASSA-PKCS1-v1_5 returned null');
      }
      result.releasedBy(arena);
      return result.copyToDartBytes();
    } on jni.JThrowable catch (e) {
      throw _rsaOperationError(e, 'JCA RSASSA-PKCS1-v1_5 signing failed');
    } finally {
      arena.releaseAll();
    }
  }

  @override
  Future<Uint8List> exportPkcs8Key() async => Uint8List.fromList(_keyData);

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async =>
      _exportJwkRsaPrivateKey(
        _keyData,
        jwkAlg: _hash._rsassaPkcs1v15JwkAlg,
        jwkUse: 'sig',
      );
}

final class _StaticRsaSsaPkcs1V15PublicKeyImpl
    implements StaticRsaSsaPkcs1v15PublicKeyImpl {
  const _StaticRsaSsaPkcs1V15PublicKeyImpl();

  @override
  Future<RsaSsaPkcs1V15PublicKeyImpl> importSpkiKey(
    List<int> keyData,
    HashImpl hash,
  ) async {
    final h = _rsaHashFromHash(hash);
    return _RsaSsaPkcs1V15PublicKeyImpl(
      _importSpkiRsaPublicKey(_asUint8List(keyData)),
      h,
    );
  }

  @override
  Future<RsaSsaPkcs1V15PublicKeyImpl> importJsonWebKey(
    Map<String, dynamic> jwk,
    HashImpl hash,
  ) async {
    final h = _rsaHashFromHash(hash);
    return _RsaSsaPkcs1V15PublicKeyImpl(
      _importJwkRsaPublicKey(
        jwk,
        expectedAlg: h._rsassaPkcs1v15JwkAlg,
        expectedUse: 'sig',
      ),
      h,
    );
  }
}

final class _RsaSsaPkcs1V15PublicKeyImpl
    implements RsaSsaPkcs1V15PublicKeyImpl {
  _RsaSsaPkcs1V15PublicKeyImpl(Uint8List keyData, this._hash)
    : _keyData = Uint8List.fromList(keyData);

  final Uint8List _keyData;
  final _HashImpl _hash;

  @override
  Future<bool> verifyBytes(List<int> signature, List<int> data) =>
      verifyStream(signature, Stream.value(data));

  @override
  Future<bool> verifyStream(List<int> signature, Stream<List<int>> data) async {
    final arena = jni.Arena();
    try {
      final key = _rsaPublicKeyFromSpki(arena, _keyData);
      final verifier = _createRsaSsaPkcs1V15Signature(arena, _hash);
      verifier.initVerify(key);

      final buffer = jni.JByteArray(_defaultChunkSize)..releasedBy(arena);
      await for (final chunk in data) {
        _updateRsaSignature(verifier, buffer, chunk);
      }

      final suppliedSignature = arena.copyToJByteArray(_asUint8List(signature));
      try {
        return verifier.verify(suppliedSignature);
      } on jni.JThrowable catch (e) {
        // Invalid signature encodings are verification failures, not operation
        // failures. Release the attacker-triggerable Java throwable promptly.
        e.release();
        return false;
      }
    } on jni.JThrowable catch (e) {
      throw _rsaOperationError(e, 'JCA RSASSA-PKCS1-v1_5 verification failed');
    } finally {
      arena.releaseAll();
    }
  }

  @override
  Future<Uint8List> exportSpkiKey() async => Uint8List.fromList(_keyData);

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async =>
      _exportJwkRsaPublicKey(
        _keyData,
        jwkAlg: _hash._rsassaPkcs1v15JwkAlg,
        jwkUse: 'sig',
      );
}

Signature _createRsaSsaPkcs1V15Signature(jni.Arena arena, _HashImpl hash) {
  final algorithm = hash._rsassaPkcs1v15JcaName.toJString()..releasedBy(arena);
  final signature = Signature.getInstance(algorithm);
  if (signature == null) {
    throw AssertionError(
      'JCA Signature(${hash._rsassaPkcs1v15JcaName}) returned null',
    );
  }
  signature.releasedBy(arena);
  return signature;
}

void _updateRsaSignature(
  Signature signature,
  jni.JByteArray buffer,
  List<int> chunk,
) {
  final bytes = _asUint8List(chunk);
  var offset = 0;
  while (offset < bytes.length) {
    final remaining = bytes.length - offset;
    final length = math.min(remaining, _defaultChunkSize);
    buffer.setRange(0, length, bytes, offset);
    signature.update$2(buffer, 0, length);
    offset += length;
  }
}
