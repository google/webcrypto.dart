import 'dart:ffi';
import 'dart:isolate' show Isolate;
import 'dart:cli' as cli;

/// Dynamically loaded boringssl library.
final _boringssl = () {
  // Use symbols from the dart executable
  final library = DynamicLibrary.executable();

  /*
  // Using symbols from boringssl in this package.
  const rootLibrary = 'package:webcrypto/webcrypto.dart';
  final u = cli
      .waitFor(Isolate.resolvePackageUri(Uri.parse(rootLibrary)))
      .resolve('../third_party/boringssl/lib/');
  // ALways load libcrypto.so first, as it's required by libssl.so
  DynamicLibrary.open(u.resolve('libcrypto.so').toFilePath());
  final library = DynamicLibrary.open(u.resolve('libssl.so').toFilePath());
  */

  // CRYPTO_library_init initializes the crypto library. It must be called if
  // the library is built with BORINGSSL_NO_STATIC_INITIALIZER. Otherwise, it
  // does nothing and a static initializer is used instead. It is safe to call
  // this function multiple times and concurrently from multiple threads.
  //
  // On some ARM configurations, this function may require filesystem access
  // and should be called before entering a sandbox.
  //
  // OPENSSL_EXPORT void CRYPTO_library_init(void);
  final CRYPTO_library_init = library
      .lookup<NativeFunction<Void Function()>>('CRYPTO_library_init')
      .asFunction<void Function()>();

  // Always initalize BoringSSL to be on the safe side.
  CRYPTO_library_init();

  return library;
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
