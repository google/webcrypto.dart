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

_HashImpl _hmacHashFromHash(HashImpl hash) {
  if (hash is _HashImpl) {
    return hash;
  }
  throw AssertionError('Custom implementations of HashImpl are not supported.');
}

extension _HmacHashMetadata on _HashImpl {
  String get _hmacJcaName {
    return switch (_jcaName) {
      'SHA-1' => 'HmacSHA1',
      'SHA-256' => 'HmacSHA256',
      'SHA-384' => 'HmacSHA384',
      'SHA-512' => 'HmacSHA512',
      _ => throw StateError('Unsupported hash algorithm: $_jcaName'),
    };
  }

  String get _hmacJwkAlg {
    return switch (_jcaName) {
      'SHA-1' => 'HS1',
      'SHA-256' => 'HS256',
      'SHA-384' => 'HS384',
      'SHA-512' => 'HS512',
      _ => throw StateError('Unsupported hash algorithm: $_jcaName'),
    };
  }

  int get _hmacDefaultLengthBits {
    return switch (_jcaName) {
      'SHA-1' => 160,
      'SHA-256' => 256,
      'SHA-384' => 384,
      'SHA-512' => 512,
      _ => throw StateError('Unsupported hash algorithm: $_jcaName'),
    };
  }
}

final class _StaticHmacSecretKeyImpl implements StaticHmacSecretKeyImpl {
  const _StaticHmacSecretKeyImpl();

  @override
  Future<HmacSecretKeyImpl> importRawKey(
    List<int> keyData,
    HashImpl hash, {
    int? length,
  }) async => _HmacSecretKeyImpl(
    _asUint8ListZeroedToBitLength(keyData, length),
    _hmacHashFromHash(hash),
  );

  @override
  Future<HmacSecretKeyImpl> importJsonWebKey(
    Map<String, dynamic> jwk,
    HashImpl hash, {
    int? length,
  }) {
    final h = _hmacHashFromHash(hash);
    final key = JsonWebKey.fromJson(jwk);

    void checkJwk(bool condition, String prop, String message) =>
        _checkData(condition, 'JWK property "$prop" $message');

    checkJwk(key.kty == 'oct', 'kty', 'must be "oct"');
    checkJwk(key.k != null, 'k', 'must be present');
    checkJwk(
      key.use == null || key.use == 'sig',
      'use',
      'must be "sig", if present',
    );
    checkJwk(
      key.alg == null || key.alg == h._hmacJwkAlg,
      'alg',
      'must be "${h._hmacJwkAlg}"',
    );

    final keyData = _jwkDecodeBase64UrlNoPadding(key.k!, 'k');
    return importRawKey(keyData, hash, length: length);
  }

  @override
  Future<HmacSecretKeyImpl> generateKey(HashImpl hash, {int? length = 32}) {
    final h = _hmacHashFromHash(hash);
    length ??= h._hmacDefaultLengthBits;
    final keyData = _randomBytes((length + 7) ~/ 8);
    return importRawKey(keyData, hash, length: length);
  }
}

final class _HmacSecretKeyImpl implements HmacSecretKeyImpl {
  _HmacSecretKeyImpl(this._keyData, this._hash);

  final Uint8List _keyData;
  final _HashImpl _hash;

  @override
  Future<Uint8List> signBytes(List<int> data) async {
    final mac = _createMac();
    try {
      final result = jni.using((arena) {
        final input = jni.JByteArray.from(data)..releasedBy(arena);
        final result = mac.doFinal$2(input);
        if (result == null) {
          throw operationError('JCA Mac(${_hash._hmacJcaName}) returned null');
        }
        result.releasedBy(arena);
        return result.copyToDartBytes();
      });
      return result;
    } finally {
      mac.release();
    }
  }

  @override
  Future<Uint8List> signStream(Stream<List<int>> data) async {
    final mac = _createMac();
    try {
      await for (final chunk in data) {
        jni.using((arena) {
          final input = jni.JByteArray.from(chunk)..releasedBy(arena);
          mac.update$1(input);
        });
      }

      final result = mac.doFinal();
      if (result == null) {
        throw operationError('JCA Mac(${_hash._hmacJcaName}) returned null');
      }
      try {
        return result.copyToDartBytes();
      } finally {
        result.release();
      }
    } finally {
      mac.release();
    }
  }

  @override
  Future<bool> verifyBytes(List<int> signature, List<int> data) async {
    return _constantTimeEquals(signature, await signBytes(data));
  }

  @override
  Future<bool> verifyStream(List<int> signature, Stream<List<int>> data) async {
    return _constantTimeEquals(signature, await signStream(data));
  }

  @override
  Future<Uint8List> exportRawKey() async => Uint8List.fromList(_keyData);

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async {
    return JsonWebKey(
      kty: 'oct',
      use: 'sig',
      alg: _hash._hmacJwkAlg,
      k: _jwkEncodeBase64UrlNoPadding(_keyData),
    ).toJson();
  }

  Mac _createMac() {
    return jni.using((arena) {
      final algorithm = jni.JString.fromString(_hash._hmacJcaName)
        ..releasedBy(arena);
      final keyData = jni.JByteArray.from(_keyData)..releasedBy(arena);
      final key = SecretKeySpec(keyData, algorithm)..releasedBy(arena);

      final mac = Mac.getInstance(algorithm);
      if (mac == null) {
        throw operationError('JCA Mac(${_hash._hmacJcaName}) is unavailable');
      }

      try {
        mac.init(key);
      } catch (_) {
        mac.release();
        rethrow;
      }
      return mac;
    });
  }
}

bool _constantTimeEquals(List<int> a, List<int> b) {
  if (a.length != b.length) {
    return false;
  }

  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}
