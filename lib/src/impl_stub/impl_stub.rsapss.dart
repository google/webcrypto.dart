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

final class _StaticRsaPssPrivateKeyImpl implements StaticRsaPssPrivateKeyImpl {
  const _StaticRsaPssPrivateKeyImpl();

  @override
  Future<RsaPssPrivateKeyImpl> importPkcs8Key(
    List<int> keyData,
    HashImpl hash,
  ) =>
      throw UnimplementedError('Not implemented');

  @override
  Future<RsaPssPrivateKeyImpl> importJsonWebKey(
    Map<String, dynamic> jwk,
    HashImpl hash,
  ) =>
      throw UnimplementedError('Not implemented');

  @override
  Future<(RsaPssPrivateKeyImpl, RsaPssPublicKeyImpl)> generateKey(
    int modulusLength,
    BigInt publicExponent,
    HashImpl hash,
  ) =>
      throw UnimplementedError('Not implemented');
}

final class _StaticRsaPssPublicKeyImpl implements StaticRsaPssPublicKeyImpl {
  const _StaticRsaPssPublicKeyImpl();

  @override
  Future<RsaPssPublicKeyImpl> importSpkiKey(
    List<int> keyData,
    HashImpl hash,
  ) =>
      throw UnimplementedError('Not implemented');

  @override
  Future<RsaPssPublicKeyImpl> importJsonWebKey(
    Map<String, dynamic> jwk,
    HashImpl hash,
  ) =>
      throw UnimplementedError('Not implemented');
}
