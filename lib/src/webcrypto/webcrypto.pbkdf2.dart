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
abstract class Pbkdf2SecretKey {
  Pbkdf2SecretKey._(); // keep the constructor private.

  static Future<Pbkdf2SecretKey> importRawKey(List<int> keyData) {
    ArgumentError.checkNotNull(keyData, 'keyData');

    return impl.pbkdf2SecretKey_importRawKey(keyData);
  }

  Future<Uint8List> deriveBits(
    int length,
    Hash hash,
    List<int> salt,
    int iterations,
  );
}
