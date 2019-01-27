#include "utils.h"
#include <openssl/mem.h>

/// Signature: (Uint8List a, Uint8List b) -> Bool | String
void compare(Dart_NativeArguments args) {
  ARGUMENT_COUNT_OR_RETURN(2);
  DEFINE_UINT8LIST_ARG_OR_RETURN(0, handleA);
  DEFINE_UINT8LIST_ARG_OR_RETURN(1, handleB);

  ACCESS_UINT8LIST_OR_RETURN(handleA, dataA, lengthA);
  ACCESS_UINT8LIST_OR_RETURN(handleB, dataB, lengthB);

  // If lengths don't match return false
  if (lengthA != lengthB) {
    Dart_SetBooleanReturnValue(args, false);
    return;
  }

  // Do a constant time comparison
  bool isEqual = CRYPTO_memcmp(dataA, dataB, lengthA) == 0;
  Dart_SetBooleanReturnValue(args, isEqual);
}