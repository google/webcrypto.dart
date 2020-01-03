import 'dart:ffi';
import 'types.dart';
import 'helpers.dart';
import 'bytestring.dart';

// See:
// https://commondatastorage.googleapis.com/chromium-boringssl-docs/hkdf.h.html

//---------------------- HKDF.

/// HKDF computes HKDF (as specified by RFC 5869) of initial keying material
/// secret with salt and info using digest, and outputs out_len bytes to
/// out_key. It returns one on success and zero on error.
///
/// HKDF is an Extract-and-Expand algorithm. It does not do any key stretching,
/// and as such, is not suited to be used alone to generate a key from a
/// password.
///
/// ```c
/// OPENSSL_EXPORT int HKDF(uint8_t *out_key, size_t out_len, const EVP_MD *digest,
///                         const uint8_t *secret, size_t secret_len,
///                         const uint8_t *salt, size_t salt_len,
///                         const uint8_t *info, size_t info_len);
/// ```
final HKDF = lookup('HKDF')
    .lookupFunc<
        Int32 Function(
      Pointer<Bytes>,
      IntPtr,
      Pointer<EVP_MD>,
      Pointer<Bytes>,
      IntPtr,
      Pointer<Bytes>,
      IntPtr,
      Pointer<Bytes>,
      IntPtr,
    )>()
    .asFunction<
        int Function(
      Pointer<Bytes>,
      int,
      Pointer<EVP_MD>,
      Pointer<Bytes>,
      int,
      Pointer<Bytes>,
      int,
      Pointer<Bytes>,
      int,
    )>();

/// From `hkdf.h`
///
/// ```c
/// #define HKDF_R_OUTPUT_TOO_LARGE 100
/// ```
const int HKDF_R_OUTPUT_TOO_LARGE = 100;
