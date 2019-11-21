import 'dart:ffi';
import 'types.dart';
import 'helpers.dart';

// See:
// https://commondatastorage.googleapis.com/chromium-boringssl-docs/err.h.html

/// ERR_get_error gets the packed error code for the least recent error and
/// removes that error from the queue. If there are no errors in the queue then
/// it returns zero.
///
///```c
/// uint32_t ERR_get_error(void);
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
/// void ERR_error_string_n(uint32_t packed_error, char *buf,
///                                        size_t len);
/// ```
final ERR_error_string_n = lookup('ERR_error_string_n')
    .lookupFunc<Void Function(Uint32, Pointer<Bytes>, IntPtr)>()
    .asFunction<void Function(int, Pointer<Bytes>, int)>();

/// ERR_clear_error clears the error queue for the current thread.
///
///```c
/// void ERR_clear_error(void);
///```
final ERR_clear_error = lookup('ERR_clear_error')
    .lookupFunc<Void Function()>()
    .asFunction<void Function()>();
