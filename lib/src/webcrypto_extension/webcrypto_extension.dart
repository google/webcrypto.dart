import 'dart:typed_data';
// just test setup
import 'dart-ext:webcrypto_extension';

// The simplest way to call native code: top-level functions.
int systemRand() native "SystemRand";

String getRandomValues(Uint8List data) native "getRandomValues";
