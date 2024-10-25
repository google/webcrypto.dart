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

part of 'impl_js.dart';

class _HashImpl implements HashImpl {
  final String _algorithm;
  const _HashImpl(this._algorithm);

  @override
  Future<Uint8List> digestBytes(List<int> data) async {
    return await _handleDomException(() async {
      final result = await subtle.digest(
        _algorithm,
        Uint8List.fromList(data),
      );
      return result.asUint8List();
    });
  }

  @override
  Future<Uint8List> digestStream(Stream<List<int>> data) async {
    return await digestBytes(await _bufferStream(data));
  }

  @override
  String hmacJwkAlg(HashImpl hash) {
    final algorithm = _getHashAlgorithm(hash);
    switch (algorithm) {
      case 'SHA-1':
        return 'HS1';
      case 'SHA-256':
        return 'HS256';
      case 'SHA-384':
        return 'HS384';
      case 'SHA-512':
        return 'HS512';
      default:
        assert(false); // This should never happen!
        throw UnsupportedError('hash is not supported');
    }
  }

  @override
  String rsaOaepJwkAlg(HashImpl hash) {
    final algorithm = _getHashAlgorithm(hash);
    switch (algorithm) {
      case 'SHA-1':
        return 'RSA-OAEP';
      case 'SHA-256':
        return 'RSA-OAEP-256';
      case 'SHA-384':
        return 'RSA-OAEP-384';
      case 'SHA-512':
        return 'RSA-OAEP-512';
      default:
        assert(false); // This should never happen!
        throw UnsupportedError('hash is not supported');
    }
  }

  @override
  String rsaPssJwkAlg(HashImpl hash) {
    final algorithm = _getHashAlgorithm(hash);
    switch (algorithm) {
      case 'SHA-1':
        return 'PS1';
      case 'SHA-256':
        return 'PS256';
      case 'SHA-384':
        return 'PS384';
      case 'SHA-512':
        return 'PS512';
      default:
        assert(false); // This should never happen!
        throw UnsupportedError('hash is not supported');
    }
  }

  @override
  String rsassaPkcs1V15JwkAlg(HashImpl hash) {
    final algorithm = _getHashAlgorithm(hash);
    switch (algorithm) {
      case 'SHA-1':
        return 'RS1';
      case 'SHA-256':
        return 'RS256';
      case 'SHA-384':
        return 'RS384';
      case 'SHA-512':
        return 'RS512';
      default:
        assert(false); // This should never happen!
        throw UnsupportedError('hash is not supported');
    }
  }
}

const HashImpl sha1 = _HashImpl('SHA-1');
const HashImpl sha256 = _HashImpl('SHA-256');
const HashImpl sha384 = _HashImpl('SHA-384');
const HashImpl sha512 = _HashImpl('SHA-512');

/// Get the algorithm from [hash] or throw an [ArgumentError].
String _getHashAlgorithm(HashImpl hash) {
  if (hash is _HashImpl) {
    return hash._algorithm;
  }
  throw ArgumentError.value(
    hash,
    'hash',
    'Only built-in hash functions is allowed',
  );
}
