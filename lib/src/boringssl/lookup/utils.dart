import 'dart:io' show Platform, File;
import 'finddotdarttool.dart';
import 'dart:ffi';
import 'symbols.generated.dart';

/// Get platform-dependent library filename for the binary webcrypto library.
String get libraryFileName {
  const libraryName = 'webcrypto';
  if (Platform.isWindows) {
    return '$libraryName.dll';
  }
  if (Platform.isLinux) {
    return 'lib$libraryName.so';
  }
  if (Platform.isMacOS) {
    return 'lib$libraryName.dylib';
  }
  throw UnsupportedError(
    'Platform ${Platform.operatingSystem} is unsupported or embed '
    'the binary webcrypto library for package:webcrypto',
  );
}

/// Look for the webcrypto binary library in the `.dart_tool/webcrypto/` folder.
///
/// Returns `null` if it could not be found.
Pointer<Void> Function(Sym) lookupLibraryInDotDartTool() {
  final dotDartTool = findDotDartTool();
  if (dotDartTool == null) {
    return null;
  }

  final libraryFile = File.fromUri(
    dotDartTool.resolve('webcrypto/$libraryFileName'),
  );
  if (libraryFile.existsSync()) {
    final library = DynamicLibrary.open(libraryFile.path);

    // Try to lookup the 'webcrypto_lookup_symbol' symbol
    // ignore: non_constant_identifier_names
    final webcrypto_lookup_symbol = library
        .lookup<NativeFunction<Pointer<Void> Function(Int32)>>(
          'webcrypto_lookup_symbol',
        )
        .asFunction<Pointer<Void> Function(int)>();

    // Return a function from Sym to lookup using `webcrypto_lookup_symbol`
    return (Sym s) => webcrypto_lookup_symbol(s.index);
  }
  return null;
}
