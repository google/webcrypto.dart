// Copyright 2025 Google LLC
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

abstract interface class StaticEd25519PrivateKeyImpl {
  Future<Ed25519PrivateKeyImpl> importPkcs8Key(List<int> keyData);
  Future<Ed25519PrivateKeyImpl> importJsonWebKey(Map<String, dynamic> jwk);
  Future<(Ed25519PrivateKeyImpl, Ed25519PublicKeyImpl)> generateKey();
}

abstract interface class Ed25519PrivateKeyImpl {
  Future<Uint8List> signBytes(List<int> data);
  Future<Uint8List> exportPkcs8Key();
  Future<Map<String, dynamic>> exportJsonWebKey();
}

abstract interface class StaticEd25519PublicKeyImpl {
  Future<Ed25519PublicKeyImpl> importRawKey(List<int> keyData);
  Future<Ed25519PublicKeyImpl> importJsonWebKey(Map<String, dynamic> jwk);
  Future<Ed25519PublicKeyImpl> importSpkiKey(List<int> keyData);
}

abstract interface class Ed25519PublicKeyImpl {
  Future<bool> verifyBytes(List<int> signature, List<int> data);
  Future<Uint8List> exportRawKey();
  Future<Uint8List> exportSpkiKey();
  Future<Map<String, dynamic>> exportJsonWebKey();
}
