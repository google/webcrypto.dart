// Copyright 2025 Google LLC
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

part of 'impl_js.dart';

const _x25519Algorithm = subtle.Algorithm(name: 'X25519');

final class _StaticX25519PrivateKeyImpl implements StaticX25519PrivateKeyImpl {
  const _StaticX25519PrivateKeyImpl();

  @override
  Future<(X25519PrivateKeyImpl, X25519PublicKeyImpl)> generateKey() async {
    final kp = await _generateKeyPair(
      _x25519Algorithm,
      _usagesDeriveBits,
    );
    return (
      _X25519PrivateKeyImpl(kp.privateKey),
      _X25519PublicKeyImpl(kp.publicKey),
    );
  }

  @override
  Future<X25519PrivateKeyImpl> importJsonWebKey(
    Map<String, dynamic> jwk,
  ) async {
    return _X25519PrivateKeyImpl(await _importJsonWebKey(
      jwk,
      _x25519Algorithm,
      _usagesDeriveBits,
      'private',
    ));
  }

  @override
  Future<X25519PrivateKeyImpl> importPkcs8Key(List<int> keyData) async {
    return _X25519PrivateKeyImpl(
      await _importKey(
        'pkcs8',
        keyData,
        _x25519Algorithm,
        _usagesDeriveBits,
        'private',
      ),
    );
  }
}

final class _X25519PrivateKeyImpl implements X25519PrivateKeyImpl {
  final subtle.JSCryptoKey _key;

  _X25519PrivateKeyImpl(this._key);

  @override
  String toString() {
    return 'Instance of \'X25519PrivateKeyImpl\'';
  }

  @override
  Future<Uint8List> deriveBits(
    int length,
    X25519PublicKeyImpl publicKey,
  ) async {
    if (publicKey is! _X25519PublicKeyImpl) {
      throw ArgumentError.value(
        publicKey,
        'publicKey',
        'custom implementations of X25519PublicKeyImpl is not supported',
      );
    }
    final lengthInBytes = (length / 8).ceil();
    final derived = await _deriveBits(
      subtle.Algorithm(
        name: _x25519Algorithm.name,
        public: publicKey._key,
      ),
      _key,
      lengthInBytes * 8,
      invalidAccessErrorIsArgumentError: true,
    );

    // Only return the first [length] bits from derived.
    final zeroBits = lengthInBytes * 8 - length;
    assert(zeroBits < 8);
    if (zeroBits > 0) {
      derived.last &= ((0xff << zeroBits) & 0xff);
    }
    return derived;
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() => _exportJsonWebKey(_key);

  @override
  Future<Uint8List> exportPkcs8Key() => _exportKey('pkcs8', _key);
}

final class _StaticX25519PublicKeyImpl implements StaticX25519PublicKeyImpl {
  const _StaticX25519PublicKeyImpl();

  @override
  Future<X25519PublicKeyImpl> importJsonWebKey(Map<String, dynamic> jwk) async {
    return _X25519PublicKeyImpl(
      await _importJsonWebKey(
        jwk,
        _x25519Algorithm,
        [],
        'public',
      ),
    );
  }

  @override
  Future<X25519PublicKeyImpl> importRawKey(List<int> keyData) async {
    return _X25519PublicKeyImpl(
      await _importKey(
        'raw',
        keyData,
        _x25519Algorithm,
        [],
        'public',
      ),
    );
  }

  @override
  Future<X25519PublicKeyImpl> importSpkiKey(List<int> keyData) async {
    return _X25519PublicKeyImpl(
      await _importKey(
        'spki',
        keyData,
        _x25519Algorithm,
        [],
        'public',
      ),
    );
  }
}

final class _X25519PublicKeyImpl implements X25519PublicKeyImpl {
  final subtle.JSCryptoKey _key;

  _X25519PublicKeyImpl(this._key);

  @override
  String toString() {
    return 'Instance of \'X25519PublicKeyImpl\'';
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() => _exportJsonWebKey(_key);

  @override
  Future<Uint8List> exportRawKey() => _exportKey('raw', _key);

  @override
  Future<Uint8List> exportSpkiKey() => _exportKey('spki', _key);
}
