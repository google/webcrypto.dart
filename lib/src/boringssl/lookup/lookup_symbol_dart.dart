import 'dart:ffi';
import 'symbols.generated.dart';
import 'utils.dart';

/// Dynamically load `webcrypto_lookup_symbol` function.
final Pointer<Void> Function(Sym) lookupSymbol = () {
  final lookup = lookupLibraryInDotDartTool();
  if (lookup != null) {
    return lookup;
  }

  try {
    // If there is no binary webcrypto library to be found we check if the
    // current executable already contains BoringSSL symbols. This happens to be
    // the case for the Dart Linux release at-least.
    final library = DynamicLibrary.executable();

    // CRYPTO_library_init initializes the crypto library. It must be called if
    // the library is built with BORINGSSL_NO_STATIC_INITIALIZER. Otherwise, it
    // does nothing and a static initializer is used instead. It is safe to call
    // this function multiple times and concurrently from multiple threads.
    //
    // On some ARM configurations, this function may require filesystem access
    // and should be called before entering a sandbox.
    //
    // OPENSSL_EXPORT void CRYPTO_library_init(void);
    // ignore: non_constant_identifier_names
    final CRYPTO_library_init = library
        .lookup<NativeFunction<Void Function()>>('CRYPTO_library_init')
        .asFunction<void Function()>();

    // Always initalize BoringSSL to be on the safe side.
    CRYPTO_library_init();

    return (Sym s) => library.lookup<Void>(s.name);
  } on ArgumentError {
    // pass, we'll throw UnsupportedError a few lines further down.
  }

  throw UnsupportedError(
    'package:webcrypto cannot be used from Dart or `pub run test` '
    'unless `pub run webcrypto:setup` has been run for the current '
    'root project.',
  );
}();
