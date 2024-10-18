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

final class _StaticHmacSecretKeyImpl implements StaticHmacSecretKeyImpl {
  const _StaticHmacSecretKeyImpl();

  @override
  Future<HmacSecretKeyImpl> importRawKey(List<int> keyData, Hash hash,
      {int? length}) {
    throw UnimplementedError('Not implemented');
  }

  @override
  Future<HmacSecretKeyImpl> importJsonWebKey(
      Map<String, dynamic> jwk, Hash hash,
      {int? length}) {
    throw UnimplementedError('Not implemented');
  }

  @override
  Future<HmacSecretKeyImpl> generateKey(Hash hash, {int? length = 32}) {
    throw UnimplementedError('Not implemented');
  }
}
