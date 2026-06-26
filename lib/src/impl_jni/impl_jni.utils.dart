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

part of 'impl_jni.dart';

extension _JByteArrayCopy on jni.JByteArray {
  /// Copies this JVM byte array into Dart-owned memory.
  ///
  /// `getRange` returns a typed list backed by a native buffer whose lifetime
  /// is finalizer-driven. Copy once more before releasing the Java array so
  /// webcrypto callers receive a normal Dart-managed [Uint8List].
  Uint8List copyToDartBytes() {
    final bytes = getRange(0, length);
    final view = bytes.buffer.asUint8List(bytes.offsetInBytes, bytes.length);
    return Uint8List.fromList(view);
  }
}
