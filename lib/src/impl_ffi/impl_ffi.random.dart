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

part of impl_ffi;

void fillRandomBytes(TypedData destination) {
  final dest = destination.buffer.asUint8List(
    destination.offsetInBytes,
    destination.lengthInBytes,
  );
  _withAllocation(_sslAlloc<ffi.Uint8>(dest.length),
      (ffi.Pointer<ffi.Uint8> p) {
    _checkOp(ssl.RAND_bytes(p, dest.length) == 1);
    dest.setAll(0, p.asTypedList(dest.length));
  });
}
