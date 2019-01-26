#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>

#include "utils.h"

/// Signature: dynamic getRandomValues(Uint8List data)
/// Returns: Null | String
void getRandomValues(Dart_NativeArguments args) {
  ARGUMENT_COUNT_OR_RETURN(1);
  DEFINE_UINT8LIST_ARG_OR_RETURN(0, dataHandle);
  ACCESS_UINT8LIST_OR_RETURN(dataHandle, data, length);

  // Fill data with random bytes.
  // https://commondatastorage.googleapis.com/chromium-boringssl-docs/headers.html
  if (RAND_bytes(data, length) != 1) {
    SET_RETURN_VALUE_TO_BORINGSSL_ERROR_STRING();
    return;
  }

  // Return null, indicating everything is okay.
  Dart_SetReturnValue(args, Dart_Null());
}
