import 'dart:ffi';
import 'dart:io' show Platform, File;
import 'symbols.generated.dart';
import 'utils.dart';

/// Dynamically load `webcrypto_lookup_symbol` function.
final Pointer<Void> Function(Sym) lookupSymbol = () {
  var library = Platform.isAndroid
      ? DynamicLibrary.open("libwebcrypto.so")
      : DynamicLibrary.executable();

  try {
    // Try to lookup the 'webcrypto_lookup_symbol' symbol
    // ignore: non_constant_identifier_names
    final webcrypto_lookup_symbol = library
        .lookup<NativeFunction<Pointer<Void> Function(Int32)>>(
          'webcrypto_lookup_symbol',
        )
        .asFunction<Pointer<Void> Function(int)>();

    // Return a function from Sym to lookup using `webcrypto_lookup_symbol`
    return (Sym s) => webcrypto_lookup_symbol(s.index);
  } on ArgumentError {
    final lookup = lookupLibraryInDotDartTool();
    if (lookup != null) {
      return lookup;
    }

    throw UnsupportedError(
      'package:webcrypto cannot be used from scripts or `flutter test` '
      'unless `flutter pub run webcrypto:setup` has been run for the current '
      'root project.',
    );
  }
}();
