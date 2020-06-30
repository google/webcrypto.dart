import 'dart:ffi';
import 'symbols.generated.dart';

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
