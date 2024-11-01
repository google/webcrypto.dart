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

part of 'impl_stub.dart';

final class _HashImpl implements HashImpl {
  const _HashImpl();

  @override
  Future<Uint8List> digestBytes(List<int> data) =>
      throw UnimplementedError('Not implemented');

  @override
  Future<Uint8List> digestStream(Stream<List<int>> data) =>
      throw UnimplementedError('Not implemented');

  @override
  String hmacJwkAlg(HashImpl hash) =>
      throw UnimplementedError('Not implemented');

  @override
  String rsaOaepJwkAlg(HashImpl hash) =>
      throw UnimplementedError('Not implemented');

  @override
  String rsaPssJwkAlg(HashImpl hash) =>
      throw UnimplementedError('Not implemented');

  @override
  String rsassaPkcs1V15JwkAlg(HashImpl hash) =>
      throw UnimplementedError('Not implemented');
}

const HashImpl sha1 = _HashImpl();
const HashImpl sha256 = _HashImpl();
const HashImpl sha384 = _HashImpl();
const HashImpl sha512 = _HashImpl();