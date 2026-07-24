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

final class _StaticRsaPssPrivateKeyImpl implements StaticRsaPssPrivateKeyImpl {
  const _StaticRsaPssPrivateKeyImpl();

  @override
  Future<RsaPssPrivateKeyImpl> importPkcs8Key(
    List<int> keyData,
    HashImpl hash,
  ) async {
    final h = _rsaHashFromHash(hash);
    return _RsaPssPrivateKeyImpl(
      _importPkcs8RsaPrivateKey(_asUint8List(keyData)),
      h,
    );
  }

  @override
  Future<RsaPssPrivateKeyImpl> importJsonWebKey(
    Map<String, dynamic> jwk,
    HashImpl hash,
  ) async {
    final h = _rsaHashFromHash(hash);
    return _RsaPssPrivateKeyImpl(
      _importJwkRsaPrivateKey(
        jwk,
        expectedAlg: h._rsaPssJwkAlg,
        expectedUse: 'sig',
      ),
      h,
    );
  }

  @override
  Future<(RsaPssPrivateKeyImpl, RsaPssPublicKeyImpl)> generateKey(
    int modulusLength,
    BigInt publicExponent,
    HashImpl hash,
  ) async {
    final h = _rsaHashFromHash(hash);
    final keyPair = await _generateRsaKeyPair(modulusLength, publicExponent);
    return (
      _RsaPssPrivateKeyImpl(
        _importPkcs8RsaPrivateKey(keyPair.privateKeyData),
        h,
      ),
      _RsaPssPublicKeyImpl(_importSpkiRsaPublicKey(keyPair.publicKeyData), h),
    );
  }
}

final class _RsaPssPrivateKeyImpl implements RsaPssPrivateKeyImpl {
  _RsaPssPrivateKeyImpl(this._key, this._hash);

  final _JcaKeyOwner _key;
  final _HashImpl _hash;

  @override
  Future<Uint8List> signBytes(List<int> data, int saltLength) {
    return signStream(Stream.value(data), saltLength);
  }

  @override
  Future<Uint8List> signStream(Stream<List<int>> data, int saltLength) {
    _validateRsaPssSaltLength(saltLength);
    return _signRsaPssStream(_key, _hash, data, saltLength);
  }

  @override
  Future<Uint8List> exportPkcs8Key() async =>
      _exportEncodedRsaKey(_key, 'private');

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async =>
      _exportJwkRsaPrivateKey(_key, jwkAlg: _hash._rsaPssJwkAlg, jwkUse: 'sig');
}

final class _StaticRsaPssPublicKeyImpl implements StaticRsaPssPublicKeyImpl {
  const _StaticRsaPssPublicKeyImpl();

  @override
  Future<RsaPssPublicKeyImpl> importSpkiKey(
    List<int> keyData,
    HashImpl hash,
  ) async {
    final h = _rsaHashFromHash(hash);
    return _RsaPssPublicKeyImpl(
      _importSpkiRsaPublicKey(_asUint8List(keyData)),
      h,
    );
  }

  @override
  Future<RsaPssPublicKeyImpl> importJsonWebKey(
    Map<String, dynamic> jwk,
    HashImpl hash,
  ) async {
    final h = _rsaHashFromHash(hash);
    return _RsaPssPublicKeyImpl(
      _importJwkRsaPublicKey(
        jwk,
        expectedAlg: h._rsaPssJwkAlg,
        expectedUse: 'sig',
      ),
      h,
    );
  }
}

final class _RsaPssPublicKeyImpl implements RsaPssPublicKeyImpl {
  _RsaPssPublicKeyImpl(this._key, this._hash);

  final _JcaKeyOwner _key;
  final _HashImpl _hash;

  @override
  Future<bool> verifyBytes(
    List<int> signature,
    List<int> data,
    int saltLength,
  ) {
    return verifyStream(signature, Stream.value(data), saltLength);
  }

  @override
  Future<bool> verifyStream(
    List<int> signature,
    Stream<List<int>> data,
    int saltLength,
  ) {
    _validateRsaPssSaltLength(saltLength);
    return _verifyRsaPssStream(
      _key,
      _hash,
      _asUint8List(signature),
      data,
      saltLength,
    );
  }

  @override
  Future<Uint8List> exportSpkiKey() async =>
      _exportEncodedRsaKey(_key, 'public');

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async =>
      _exportJwkRsaPublicKey(_key, jwkAlg: _hash._rsaPssJwkAlg, jwkUse: 'sig');
}

Future<Uint8List> _signRsaPssStream(
  _JcaKeyOwner key,
  _HashImpl hash,
  Stream<List<int>> data,
  int saltLength,
) async {
  final arena = jni.Arena();
  try {
    final signature = _createRsaPssSignature(arena, hash, saltLength);
    signature.initSign(key.key);

    final buffer = jni.JByteArray(_defaultChunkSize)..releasedBy(arena);
    await for (final chunk in data) {
      _updateRsaSignature(signature, buffer, chunk);
    }

    final result = signature.sign();
    if (result == null) {
      throw AssertionError('JCA RSA-PSS returned null');
    }
    result.releasedBy(arena);
    return result.copyToDartBytes();
  } on jni.JThrowable catch (e) {
    throw _rsaOperationError(e, 'JCA RSA-PSS signing failed');
  } finally {
    arena.releaseAll();
  }
}

Future<bool> _verifyRsaPssStream(
  _JcaKeyOwner key,
  _HashImpl hash,
  Uint8List suppliedSignature,
  Stream<List<int>> data,
  int saltLength,
) async {
  final arena = jni.Arena();
  try {
    final verifier = _createRsaPssSignature(arena, hash, saltLength);
    verifier.initVerify(key.key);

    final buffer = jni.JByteArray(_defaultChunkSize)..releasedBy(arena);
    await for (final chunk in data) {
      _updateRsaSignature(verifier, buffer, chunk);
    }

    final javaSignature = arena.copyToJByteArray(suppliedSignature);
    try {
      return verifier.verify(javaSignature);
    } on jni.JThrowable catch (e) {
      // Invalid signature encodings are verification failures, not operation
      // failures. Release the attacker-triggerable Java throwable promptly.
      e.release();
      return false;
    }
  } on jni.JThrowable catch (e) {
    throw _rsaOperationError(e, 'JCA RSA-PSS verification failed');
  } finally {
    arena.releaseAll();
  }
}

Signature _createRsaPssSignature(
  jni.Arena arena,
  _HashImpl hash,
  int saltLength,
) {
  final signature = _getRsaPssSignature(arena, hash);

  final hashName = hash._jcaName.toJString()..releasedBy(arena);
  final mgfName = 'MGF1'.toJString()..releasedBy(arena);
  final mgfParameters = MGF1ParameterSpec(hashName)..releasedBy(arena);
  final parameters = PSSParameterSpec(
    hashName,
    mgfName,
    mgfParameters,
    saltLength,
    1,
  )..releasedBy(arena);
  signature.parameter = parameters;
  return signature;
}

Signature _getRsaPssSignature(jni.Arena arena, _HashImpl hash) {
  try {
    return _getRsaPssSignatureByName(arena, 'RSASSA-PSS');
  } on jni.JThrowable catch (e) {
    // Some Android providers expose hash-specific PSS names, while desktop
    // JCA providers commonly expose the standard parameterized name.
    e.release();
    return _getRsaPssSignatureByName(arena, hash._rsaPssJcaName);
  }
}

Signature _getRsaPssSignatureByName(jni.Arena arena, String name) {
  final algorithm = name.toJString()..releasedBy(arena);
  final signature = Signature.getInstance(algorithm);
  if (signature == null) {
    throw AssertionError('JCA Signature($name) returned null');
  }
  signature.releasedBy(arena);
  return signature;
}

void _validateRsaPssSaltLength(int saltLength) {
  if (saltLength < 0) {
    throw ArgumentError.value(
      saltLength,
      'saltLength',
      'must be a positive integer',
    );
  }
}

extension _RsaPssHashMetadata on _HashImpl {
  String get _rsaPssJcaName {
    return switch (_jcaName) {
      'SHA-1' => 'SHA1withRSA/PSS',
      'SHA-256' => 'SHA256withRSA/PSS',
      'SHA-384' => 'SHA384withRSA/PSS',
      'SHA-512' => 'SHA512withRSA/PSS',
      _ => throw AssertionError('Unknown hash algorithm: $_jcaName'),
    };
  }

  String get _rsaPssJwkAlg {
    return switch (_jcaName) {
      'SHA-1' => 'PS1',
      'SHA-256' => 'PS256',
      'SHA-384' => 'PS384',
      'SHA-512' => 'PS512',
      _ => throw AssertionError('Unknown hash algorithm: $_jcaName'),
    };
  }
}
