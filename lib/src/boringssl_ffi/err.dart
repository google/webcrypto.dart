import 'dart:ffi';
import 'dart:convert' show utf8;
import 'types.dart';
import 'helpers.dart';

// See:
// https://commondatastorage.googleapis.com/chromium-boringssl-docs/err.h.html

/// ERR_get_error gets the packed error code for the least recent error and
/// removes that error from the queue. If there are no errors in the queue then
/// it returns zero.
///
///```c
/// OPENSSL_EXPORT uint32_t ERR_get_error(void);
///```
final ERR_get_error = lookup('ERR_get_error')
    .lookupFunc<Uint32 Function()>()
    .asFunction<int Function()>();

/// ERR_error_string_n generates a human-readable string representing
/// packed_error and places it at buf. It writes at most len bytes (including
/// the terminating NUL) and truncates the string if necessary. If len is
/// greater than zero then buf is always NUL terminated.
///
/// The string will have the following format:
/// ```
/// error:[error code]:[library name]:OPENSSL_internal:[reason string]
/// ```
/// error code is an 8 digit hexadecimal number; library name and reason string
/// are ASCII text.
///
/// ```c
/// OPENSSL_EXPORT void ERR_error_string_n(uint32_t packed_error, char *buf,
///                                        size_t len);
/// ```
final ERR_error_string_n = lookup('ERR_error_string_n')
    .lookupFunc<void Function(Uint32, Bytes, IntPtr)>()
    .asFunction<void Function(int, Bytes, int)>();

/// ERR_clear_error clears the error queue for the current thread.
///
///```c
/// OPENSSL_EXPORT void ERR_clear_error(void);
///```
final ERR_clear_error = lookup('ERR_clear_error')
    .lookupFunc<void Function()>()
    .asFunction<void Function()>();

/// Extract latest error on this thread as [String] and clear the error queue
/// for this thread.
///
/// Returns `null` if there is no error.
String extractError() {
  try {
    // Get the error.
    final err = ERR_get_error();
    if (err == 0) {
      return null;
    }
    const N = 4096; // Max error message size
    final data = withOutputPointer(N, (Bytes p) {
      ERR_error_string_n(err, p, N);
    });
    // Take everything until '\0'
    return utf8.decode(data.takeWhile((i) => i != 0).toList());
  } finally {
    // Always clear error queue, so we continue
    ERR_clear_error();
  }
}
