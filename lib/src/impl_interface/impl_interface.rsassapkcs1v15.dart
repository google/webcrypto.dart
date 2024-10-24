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

part of 'impl_interface.dart';

abstract interface class StaticRsaSsaPkcs1v15PrivateKeyImpl {
  Future<RsaSsaPkcs1V15PrivateKeyImpl> importPkcs8Key(
      List<int> keyData, Hash hash);
  Future<RsaSsaPkcs1V15PrivateKeyImpl> importJsonWebKey(
      Map<String, dynamic> jwk, Hash hash);
  Future<(RsaSsaPkcs1V15PrivateKeyImpl, RsaSsaPkcs1V15PublicKeyImpl)>
      generateKey(int modulusLength, BigInt publicExponent, Hash hash);
}

abstract interface class RsaSsaPkcs1V15PrivateKeyImpl {
  Future<Uint8List> signBytes(List<int> data);
  Future<Uint8List> signStream(Stream<List<int>> data);
  Future<Uint8List> exportPkcs8Key();
  Future<Map<String, dynamic>> exportJsonWebKey();
}

abstract interface class StaticRsaSsaPkcs1v15PublicKeyImpl {
  Future<RsaSsaPkcs1V15PublicKeyImpl> importSpkiKey(
      List<int> keyData, Hash hash);
  Future<RsaSsaPkcs1V15PublicKeyImpl> importJsonWebKey(
      Map<String, dynamic> jwk, Hash hash);
}

abstract interface class RsaSsaPkcs1V15PublicKeyImpl {
  Future<bool> verifyBytes(List<int> signature, List<int> data);
  Future<bool> verifyStream(List<int> signature, Stream<List<int>> data);
  Future<Uint8List> exportSpkiKey();
  Future<Map<String, dynamic>> exportJsonWebKey();
}
