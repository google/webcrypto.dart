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

abstract interface class StaticEcdhPrivateKeyImpl {
  Future<EcdhPrivateKeyImpl> importPkcs8Key(
      List<int> keyData, EllipticCurve curve);
  Future<EcdhPrivateKeyImpl> importJsonWebKey(
      Map<String, dynamic> jwk, EllipticCurve curve);
  Future<(EcdhPrivateKeyImpl, EcdhPublicKeyImpl)> generateKey(
      EllipticCurve curve);
}

abstract interface class EcdhPrivateKeyImpl {
  Future<Uint8List> deriveBits(int length, EcdhPublicKeyImpl publicKey);
  Future<Uint8List> exportPkcs8Key();
  Future<Map<String, dynamic>> exportJsonWebKey();
}

abstract interface class StaticEcdhPublicKeyImpl {
  Future<EcdhPublicKeyImpl> importRawKey(
      List<int> keyData, EllipticCurve curve);
  Future<EcdhPublicKeyImpl> importSpkiKey(
      List<int> keyData, EllipticCurve curve);
  Future<EcdhPublicKeyImpl> importJsonWebKey(
      Map<String, dynamic> jwk, EllipticCurve curve);
}

abstract interface class EcdhPublicKeyImpl {
  Future<Uint8List> exportRawKey();
  Future<Uint8List> exportSpkiKey();
  Future<Map<String, dynamic>> exportJsonWebKey();
}
