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

abstract interface class StaticHkdfSecretKeyImpl {
  Future<HkdfSecretKeyImpl> importRawKey(List<int> keyData);
}

abstract interface class HkdfSecretKeyImpl {
  Future<Uint8List> deriveBits(
    int length,
    Hash hash,
    List<int> salt,
    List<int> info,
  );
}
