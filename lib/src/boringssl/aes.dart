// ignore_for_file: non_constant_identifier_names

/// This library maps symbols from:
/// https://commondatastorage.googleapis.com/chromium-boringssl-docs/aes.h.html
library aes;

//---------------------- Raw AES functions.

/// AES block size.
///
/// ```c
/// #define AES_BLOCK_SIZE 16
/// ```
const int AES_BLOCK_SIZE = 16;
