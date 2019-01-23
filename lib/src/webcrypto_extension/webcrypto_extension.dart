// just test setup
import 'dart-ext:webcrypto_extension';

// The simplest way to call native code: top-level functions.
int systemRand() native "SystemRand";
