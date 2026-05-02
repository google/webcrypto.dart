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

abstract interface class StaticX25519PrivateKeyImpl {
  Future<X25519PrivateKeyImpl> importPkcs8Key(List<int> keyData);
  Future<X25519PrivateKeyImpl> importJsonWebKey(Map<String, dynamic> jwk);
  Future<(X25519PrivateKeyImpl, X25519PublicKeyImpl)> generateKey();
}

abstract interface class X25519PrivateKeyImpl {
  Future<Uint8List> deriveBits(int length, X25519PublicKeyImpl publicKey);
  Future<Uint8List> exportPkcs8Key();
  Future<Map<String, dynamic>> exportJsonWebKey();
}

abstract interface class StaticX25519PublicKeyImpl {
  Future<X25519PublicKeyImpl> importRawKey(List<int> keyData);
  Future<X25519PublicKeyImpl> importSpkiKey(List<int> keyData);
  Future<X25519PublicKeyImpl> importJsonWebKey(Map<String, dynamic> jwk);
}

abstract interface class X25519PublicKeyImpl {
  Future<Uint8List> exportRawKey();
  Future<Uint8List> exportSpkiKey();
  Future<Map<String, dynamic>> exportJsonWebKey();
}
