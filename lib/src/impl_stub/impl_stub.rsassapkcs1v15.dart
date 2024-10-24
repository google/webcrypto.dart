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

final class _StaticRsaSsaPkcs1V15PrivateKeyImpl
    implements StaticRsaSsaPkcs1v15PrivateKeyImpl {
  const _StaticRsaSsaPkcs1V15PrivateKeyImpl();

  @override
  Future<RsaSsaPkcs1V15PrivateKeyImpl> importPkcs8Key(
    List<int> keyData,
    Hash hash,
  ) =>
      throw UnimplementedError('Not implemented');

  @override
  Future<RsaSsaPkcs1V15PrivateKeyImpl> importJsonWebKey(
    Map<String, dynamic> jwk,
    Hash hash,
  ) =>
      throw UnimplementedError('Not implemented');

  @override
  Future<(RsaSsaPkcs1V15PrivateKeyImpl, RsaSsaPkcs1V15PublicKeyImpl)>
      generateKey(
    int modulusLength,
    BigInt publicExponent,
    Hash hash,
  ) =>
          throw UnimplementedError('Not implemented');
}

final class _StaticRsaSsaPkcs1V15PublicKeyImpl
    implements StaticRsaSsaPkcs1v15PublicKeyImpl {
  const _StaticRsaSsaPkcs1V15PublicKeyImpl();

  @override
  Future<RsaSsaPkcs1V15PublicKeyImpl> importSpkiKey(
    List<int> keyData,
    Hash hash,
  ) =>
      throw UnimplementedError('Not implemented');

  @override
  Future<RsaSsaPkcs1V15PublicKeyImpl> importJsonWebKey(
    Map<String, dynamic> jwk,
    Hash hash,
  ) =>
      throw UnimplementedError('Not implemented');
}
