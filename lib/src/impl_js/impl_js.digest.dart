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

final class _HashImpl implements HashImpl {
  final String _algorithm;
  const _HashImpl(this._algorithm);

  @override
  Future<Uint8List> digestBytes(List<int> data) async {
    return await _handleDomException(() async {
      final result = await subtle.digest(_algorithm, Uint8List.fromList(data));
      return result.asUint8List();
    });
  }

  @override
  Future<Uint8List> digestStream(Stream<List<int>> data) async {
    return await digestBytes(await _bufferStream(data));
  }
}

/// Get the algorithm from [hash] or throw an [ArgumentError].
String _getHashAlgorithm(HashImpl hash) {
  if (hash is _HashImpl) {
    return hash._algorithm;
  }
  throw AssertionError('Custom implementations of HashImpl are not supported.');
}
