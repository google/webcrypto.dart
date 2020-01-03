import 'dart:ffi';
import 'types.dart';
import 'helpers.dart';

// See:
// https://commondatastorage.googleapis.com/chromium-boringssl-docs/err.h.html

//---------------------- Reading and formatting errors.

/// ERR_GET_LIB returns the library code for the error. This is one of the
/// ERR_LIB_* values.
///
/// ```c
/// #define ERR_GET_LIB(packed_error) ((int)(((packed_error) >> 24) & 0xff))
/// ```
int ERR_GET_LIB(int packed_error) => (packed_error >> 24) & 0xff;

/// ERR_GET_REASON returns the reason code for the error. This is one of
/// library-specific LIB_R_* values where LIB is the library (see ERR_GET_LIB).
/// Note that reason codes are specific to the library.
///
/// ```c
/// #define ERR_GET_REASON(packed_error) ((int)((packed_error) & 0xfff))
/// ```
int ERR_GET_REASON(int packed_error) => packed_error & 0xfff;

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

/// The "peek" functions act like the ERR_get_error functions, above, but they
/// do not remove the error from the queue.
///
/// ```c
/// OPENSSL_EXPORT uint32_t ERR_peek_error(void);
/// ```
final ERR_peek_error = lookup('ERR_peek_error')
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

//---------------------- Clearing errors.

/// ERR_clear_error clears the error queue for the current thread.
///
///```c
/// void ERR_clear_error(void);
///```
final ERR_clear_error = lookup('ERR_clear_error')
    .lookupFunc<Void Function()>()
    .asFunction<void Function()>();

//---------------------- Built-in library and reason codes.

/// The following values are built-in library codes.
///
/// ```c
/// enum {
///   ERR_LIB_NONE = 1,
///   ERR_LIB_SYS,
///   ERR_LIB_BN,
///   ERR_LIB_RSA,
///   ERR_LIB_DH,
///   ERR_LIB_EVP,
///   ERR_LIB_BUF,
///   ERR_LIB_OBJ,
///   ERR_LIB_PEM,
///   ERR_LIB_DSA,
///   ERR_LIB_X509,
///   ERR_LIB_ASN1,
///   ERR_LIB_CONF,
///   ERR_LIB_CRYPTO,
///   ERR_LIB_EC,
///   ERR_LIB_SSL,
///   ERR_LIB_BIO,
///   ERR_LIB_PKCS7,
///   ERR_LIB_PKCS8,
///   ERR_LIB_X509V3,
///   ERR_LIB_RAND,
///   ERR_LIB_ENGINE,
///   ERR_LIB_OCSP,
///   ERR_LIB_UI,
///   ERR_LIB_COMP,
///   ERR_LIB_ECDSA,
///   ERR_LIB_ECDH,
///   ERR_LIB_HMAC,
///   ERR_LIB_DIGEST,
///   ERR_LIB_CIPHER,
///   ERR_LIB_HKDF,
///   ERR_LIB_USER,
///   ERR_NUM_LIBS
/// };
/// ```
const int ERR_LIB_HKDF = 31;
