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

part of 'impl_ffi.dart';

final class _RandomImpl implements RandomImpl {
  const _RandomImpl();

  @override
  void fillRandomBytes(TypedData destination) {
    return _Scope.sync((scope) {
      final dest = destination.buffer.asUint8List(
        destination.offsetInBytes,
        destination.lengthInBytes,
      );

      final out = scope<ffi.Uint8>(dest.length);
      _checkOp(ssl.RAND_bytes(out, dest.length) == 1);
      dest.setAll(0, out.asTypedList(dest.length));
    });
  }

  @override
  String randomUUID() {
    return _Scope.sync((scope) {
      final out = scope<ffi.Uint8>(16);
      _checkOp(ssl.RAND_bytes(out, 16) == 1);

      var bytes = out.asTypedList(16);

      // Set the 4 most significant bits of bytes[6] to 0100.
      bytes[6] = (bytes[6] & 0x0F) | 0x40;

      // Set the 2 most significant bits of bytes[8] to 10.
      bytes[8] = (bytes[8] & 0x3F) | 0x80;

      return bytes
          .map((e) => e.toRadixString(16).padLeft(2, '0'))
          .join()
          .replaceAllMapped(
            RegExp(r'(\w{8})(\w{4})(\w{4})(\w{4})(\w{12})'),
            (m) => '${m[1]}-${m[2]}-${m[3]}-${m[4]}-${m[5]}',
          );
    });
  }
}
