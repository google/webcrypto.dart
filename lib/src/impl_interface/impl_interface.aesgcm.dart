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

abstract interface class StaticAesGcmSecretKeyImpl {
  Future<AesGcmSecretKeyImpl> importRawKey(List<int> keyData);
  Future<AesGcmSecretKeyImpl> importJsonWebKey(Map<String, dynamic> jwk);
  Future<AesGcmSecretKeyImpl> generateKey(int length);
}

abstract interface class AesGcmSecretKeyImpl {
  Future<Uint8List> encryptBytes(
    List<int> data,
    List<int> iv, {
    List<int>? additionalData,
    int? tagLength,
  });
  Future<Uint8List> decryptBytes(
    List<int> data,
    List<int> iv, {
    List<int>? additionalData,
    int? tagLength,
  });
  Future<Uint8List> exportRawKey();
  Future<Map<String, dynamic>> exportJsonWebKey();
}
