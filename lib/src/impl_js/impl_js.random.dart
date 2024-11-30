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

part of 'impl_js.dart';

void fillRandomBytes(TypedData destination) {
  try {
    if (destination is Uint8List) {
      final newValues = subtle.getRandomValues(destination);
      destination.setAll(0, newValues as Uint8List);
    } else if (destination is Uint16List) {
      final newValues = subtle.getRandomValues(destination);
      destination.setAll(0, newValues as Uint16List);
    } else if (destination is Uint32List) {
      final newValues = subtle.getRandomValues(destination);
      destination.setAll(0, newValues as Uint32List);
    } else if (destination is Int8List) {
      final newValues = subtle.getRandomValues(destination);
      destination.setAll(0, newValues as Int8List);
    } else if (destination is Int16List) {
      final newValues = subtle.getRandomValues(destination);
      destination.setAll(0, newValues as Int16List);
    } else if (destination is Int32List) {
      final newValues = subtle.getRandomValues(destination);
      destination.setAll(0, newValues as Int32List);
    } else {
      throw UnsupportedError(
        'Unsupported TypedData type: ${destination.runtimeType}',
      );
    }
  } on subtle.JSDomException catch (e) {
    throw _translateDomException(e);
  } on UnsupportedError {
    rethrow;
  } on Error catch (e) {
    throw _translateJavaScriptException(e);
  }
}
