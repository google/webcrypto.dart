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

/*
Dart_Handle newArgumentError(const char* message) {
Dart_Handle newNotSupportedException(const char* message) {
Dart_Handle newOperationException(const char* message) {
Dart_Handle newDataException(const char* message) {
    Dart_Handle core_lib_url =
      HandleError(Dart_NewStringFromCString("dart:core"));
  Dart_Handle argument_error_name =
      HandleError(Dart_NewStringFromCString("ArgumentError"));
  Dart_Handle core_lib = HandleError(Dart_LookupLibrary(core_lib_url));
  Dart_Handle argument_error_class =
      HandleError(Dart_GetClass(core_lib, argument_error_name));
  Dart_Handle argument_error;
  if (name != NULL) {
    char buffer[256];
    snprintf(buffer, sizeof(buffer), "Invalid arguments passed to '%s'", name);
    Dart_Handle argument_error_message =
        HandleError(Dart_NewStringFromCString(buffer));
    argument_error =
        HandleError(
            Dart_New(argument_error_class,
                     Dart_Null(),
                     1,
                     &argument_error_message));
}
*/