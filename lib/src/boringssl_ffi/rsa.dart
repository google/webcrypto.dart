import 'dart:ffi';
import 'types.dart';
import 'helpers.dart';

// See:
// https://commondatastorage.googleapis.com/chromium-boringssl-docs/rsa.h.html

/// RSA_check_key performs basic validity tests on rsa. It returns one if they
/// pass and zero otherwise. Opaque keys and public keys always pass. If it
/// returns zero then a more detailed error is available on the error queue.
///
/// ```c
/// OPENSSL_EXPORT int RSA_check_key(const RSA *rsa);
/// ```
final RSA_check_key = lookup('RSA_check_key')
    .lookupFunc<Int32 Function(RSA)>()
    .asFunction<int Function(RSA)>();
