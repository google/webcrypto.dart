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

abstract interface class StaticAesCbcSecretKeyImpl {
  Future<AesCbcSecretKeyImpl> importRawKey(List<int> keyData);
  Future<AesCbcSecretKeyImpl> importJsonWebKey(Map<String, dynamic> jwk);
  Future<AesCbcSecretKeyImpl> generateKey(int length);
}

abstract class AesCbcSecretKeyImpl {
  Future<Uint8List> encryptBytes(List<int> data, List<int> iv);
  Future<Uint8List> decryptBytes(List<int> data, List<int> iv);
  Stream<Uint8List> encryptStream(Stream<List<int>> data, List<int> iv);
  Stream<Uint8List> decryptStream(Stream<List<int>> data, List<int> iv);
  Future<Uint8List> exportRawKey();
  Future<Map<String, dynamic>> exportJsonWebKey();
}
