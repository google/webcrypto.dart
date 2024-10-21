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

abstract interface class StaticRsaOaepPrivateKeyImpl {
  Future<RsaOaepPrivateKeyImpl> importPkcs8Key(List<int> keyData, Hash hash);
  Future<RsaOaepPrivateKeyImpl> importJsonWebKey(
      Map<String, dynamic> jwk, Hash hash);
  Future<(RsaOaepPrivateKeyImpl, RsaOaepPublicKeyImpl)> generateKey(
      int modulusLength, BigInt publicExponent, Hash hash);
}

abstract interface class RsaOaepPrivateKeyImpl {
  Future<Uint8List> decryptBytes(List<int> data, {List<int>? label});
  Future<Uint8List> exportPkcs8Key();
  Future<Map<String, dynamic>> exportJsonWebKey();
}

abstract interface class StaticRsaOaepPublicKeyImpl {
  Future<RsaOaepPublicKeyImpl> importSpkiKey(List<int> keyData, Hash hash);
  Future<RsaOaepPublicKeyImpl> importJsonWebKey(
      Map<String, dynamic> jwk, Hash hash);
}

abstract interface class RsaOaepPublicKeyImpl {
  Future<Uint8List> encryptBytes(List<int> data, {List<int>? label});
  Future<Uint8List> exportSpkiKey();
  Future<Map<String, dynamic>> exportJsonWebKey();
}
