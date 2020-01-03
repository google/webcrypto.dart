import 'dart:ffi';
import 'dart:isolate' show Isolate;
import 'dart:cli' as cli;

/// Dynamically loaded boringssl library.
final _boringssl = () {
  // Use symbols from the dart executable
  // return DynamicLibrary.executable();

  // Using symbols from boringssl in this package.
  const rootLibrary = 'package:webcrypto/webcrypto.dart';
  final u = cli
      .waitFor(Isolate.resolvePackageUri(Uri.parse(rootLibrary)))
      .resolve('../third_party/boringssl/lib/');
  // ALways load libcrypto.so first, as it's required by libssl.so
  DynamicLibrary.open(u.resolve('libcrypto.so').toFilePath());
  return DynamicLibrary.open(u.resolve('libssl.so').toFilePath());
}();

/// Auxiliary for loading functions from [_boringssl].
class _Resolver {
  final String symbolName;
  _Resolver(this.symbolName);
  Pointer<NativeFunction<T>> lookupFunc<T extends Function>() =>
      _boringssl.lookup<NativeFunction<T>>(symbolName);
}

/// Helper function for looking up functions with two calls, such that
/// we don't have multiple type arguments one the same line.
_Resolver lookup(String symbol) => _Resolver(symbol);
