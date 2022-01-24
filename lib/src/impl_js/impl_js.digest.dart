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

part of impl_js;

class _Hash implements Hash {
  final String _algorithm;
  const _Hash(this._algorithm);

  @override
  Future<Uint8List> digestBytes(List<int> data) async {
    ArgumentError.checkNotNull(data, 'data');

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
}

const Hash sha1 = _Hash('SHA-1');
const Hash sha256 = _Hash('SHA-256');
const Hash sha384 = _Hash('SHA-384');
const Hash sha512 = _Hash('SHA-512');

/// Get the algorithm from [hash] or throw an [ArgumentError].
String _getHashAlgorithm(Hash hash) {
  ArgumentError.checkNotNull(hash, 'hash');

  if (hash is _Hash) {
    return hash._algorithm;
  }
  throw ArgumentError.value(
    hash,
    'hash',
    'Only built-in hash functions is allowed',
  );
}
