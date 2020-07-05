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

part of webcrypto;

@sealed
abstract class AesCtrSecretKey {
  AesCtrSecretKey._(); // keep the constructor private.

  static Future<AesCtrSecretKey> importRawKey(List<int> keyData) {
    ArgumentError.checkNotNull(keyData, 'keyData');

    return impl.aesCtr_importRawKey(keyData);
  }

  static Future<AesCtrSecretKey> importJsonWebKey(Map<String, dynamic> jwk) {
    ArgumentError.checkNotNull(jwk, 'jwk');

    return impl.aesCtr_importJsonWebKey(jwk);
  }

  static Future<AesCtrSecretKey> generateKey(int length) {
    ArgumentError.checkNotNull(length, 'length');

    return impl.aesCtr_generateKey(length);
  }

  // Note. that if counter wraps around, then this is broken on Firefox.
  Future<Uint8List> encryptBytes(
    List<int> data,
    List<int> counter,
    int length,
  );

  Stream<Uint8List> encryptStream(
    Stream<List<int>> data,
    List<int> counter,
    int length,
  );

  Future<Uint8List> decryptBytes(
    List<int> data,
    List<int> counter,
    int length,
  );

  Stream<Uint8List> decryptStream(
    Stream<List<int>> data,
    List<int> counter,
    int length,
  );

  Future<Uint8List> exportRawKey();

  Future<Map<String, dynamic>> exportJsonWebKey();
}
