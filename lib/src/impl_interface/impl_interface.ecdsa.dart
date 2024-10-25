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

abstract interface class StaticEcdsaPrivateKeyImpl {
  Future<EcdsaPrivateKeyImpl> importPkcs8Key(
      List<int> keyData, EllipticCurve curve);
  Future<EcdsaPrivateKeyImpl> importJsonWebKey(
      Map<String, dynamic> jwk, EllipticCurve curve);
  Future<(EcdsaPrivateKeyImpl, EcdsaPublicKeyImpl)> generateKey(
      EllipticCurve curve);
}

abstract interface class EcdsaPrivateKeyImpl {
  Future<Uint8List> signBytes(List<int> data, HashImpl hash);
  Future<Uint8List> signStream(Stream<List<int>> data, HashImpl hash);
  Future<Uint8List> exportPkcs8Key();
  Future<Map<String, dynamic>> exportJsonWebKey();
}

abstract interface class StaticEcdsaPublicKeyImpl {
  Future<EcdsaPublicKeyImpl> importRawKey(
      List<int> keyData, EllipticCurve curve);
  Future<EcdsaPublicKeyImpl> importJsonWebKey(
      Map<String, dynamic> jwk, EllipticCurve curve);
  Future<EcdsaPublicKeyImpl> importSpkiKey(
      List<int> keyData, EllipticCurve curve);
}

abstract interface class EcdsaPublicKeyImpl {
  Future<bool> verifyBytes(List<int> signature, List<int> data, HashImpl hash);
  Future<bool> verifyStream(
      List<int> signature, Stream<List<int>> data, HashImpl hash);
  Future<Uint8List> exportRawKey();
  Future<Uint8List> exportSpkiKey();
  Future<Map<String, dynamic>> exportJsonWebKey();
}
