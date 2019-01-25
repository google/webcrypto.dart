#include <openssl/err.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>

#include "digest.h"

#include "utils.h"
// https://commondatastorage.googleapis.com/chromium-boringssl-docs/headers.html

void getRandomValues(Dart_NativeArguments args) {
  Dart_Handle ok;

  // Check that we have a single argument
  if (Dart_GetNativeArgumentCount(args) != 1) {
    auto err = Dart_NewApiError("getRandomValues requires 1 argument");
    Dart_SetReturnValue(args, err);
    return;
  }
  // Get the single argument
  auto handle = Dart_GetNativeArgument(args, 0);
  if (Dart_IsError(handle)) {
    Dart_SetReturnValue(args, handle);
    return;
  }
  // Check the type of the argument
  if (!Dart_IsTypedData(handle)) {
    auto err = Dart_NewApiError("getRandomValues only takes Uint8List");
    Dart_SetReturnValue(args, err);
    return;
  }

  {
    // Get access to the data
    TypedData d(handle);
    if (d.isError()) {
      Dart_SetReturnValue(args, d.error);
      return;
    }

    if (d.type != Dart_TypedData_kUint8) {
      auto err = Dart_NewApiError("getRandomValues only takes Uint8List");
      Dart_SetReturnValue(args, err);
      return;
    }

    // Fill data with random bytes.
    if (RAND_bytes(static_cast<uint8_t*>(d.data), d.length) != 1) {
      auto error = ERR_get_error();
      Dart_Handle message;
      if (error != 0) {
        message = Dart_NewStringFromCString(ERR_reason_error_string(error));
      } else {
        message = Dart_NewStringFromCString("unknown error");
      }
      ERR_clear_error();
      Dart_SetReturnValue(args, message);
      return;
    }
  }

  // Return null, indicating everything is okay.
  Dart_SetReturnValue(args, Dart_Null());
}
