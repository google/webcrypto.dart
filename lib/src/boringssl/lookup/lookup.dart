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

import 'dart:ffi';

import 'symbols.generated.dart';
import '../../third_party/boringssl/generated_bindings.dart';

import 'lookup_symbol_dart.dart'
    if (dart.library.ui) 'lookup_symbol_flutter.dart';

export 'symbols.generated.dart' show Sym;

/// Auxiliary for loading functions from [_boringssl].
class SymbolResolver {
  final Sym symbolName;
  SymbolResolver._(this.symbolName);
  Pointer<NativeFunction<T>> lookupFunc<T extends Function>() {
    return lookupSymbol(symbolName).cast<NativeFunction<T>>();
  }
}

/// Helper function for looking up functions with two calls, such that
/// we don't have multiple type arguments one the same line.
SymbolResolver resolve(Sym symbol) => SymbolResolver._(symbol);

final Pointer<T> Function<T extends NativeType>(String symbolName)
    boringsslLibrary = lookup;

final BoringSsl ssl2 = BoringSsl.fromLookup(boringsslLibrary);
