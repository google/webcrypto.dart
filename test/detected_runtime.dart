import 'detected_runtime_stub.dart'
    if (dart.library.html) 'detected_runtime_html.dart';

export 'detected_runtime_stub.dart'
    if (dart.library.html) 'detected_runtime_html.dart';

/// Return `null` instead of [value] on Gecko.
///
/// PKCS8 is not support for ECDH / ECDSA on firefox:
/// https://bugzilla.mozilla.org/show_bug.cgi?id=1133698
///
/// This utility helps filter away PKCS8 test data and functions when running
/// on Firefox.
T nullOnGecko<T>(T value) => detectedRuntime == 'gecko' ? null : value;
