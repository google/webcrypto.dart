#include "hmac.h"
#include <openssl/hmac.h>
#include "digest.h"
#include "utils.h"

/// Signature: (int hashIdentifier, Uint8List keyData) -> int | String
void hmac_create(Dart_NativeArguments args) {
  ARGUMENT_COUNT_OR_RETURN(2);
  DEFINE_INT_ARG_OR_RETURN(0, hashIdentifier);
  DEFINE_UINT8LIST_ARG_OR_RETURN(1, keyDataHandle);

  // Get the algorithm
  auto algorithm = hashIdentifierToAlgorithm(hashIdentifier);
  if (algorithm == nullptr) {
    RETURN_API_ERROR("invalid hash identifier");
  }

  ACCESS_UINT8LIST_OR_RETURN(keyDataHandle, keyData, keyLength);

  // Allocate a context
  HMAC_CTX* ctx = HMAC_CTX_new();
  if (ctx == nullptr) {
    SET_RETURN_VALUE_TO_BORINGSSL_ERROR_STRING();
    return;
  }

  // Initialize the context
  if (HMAC_Init_ex(ctx, keyData, keyLength, algorithm, nullptr) != 1) {
    SET_RETURN_VALUE_TO_BORINGSSL_ERROR_STRING();
    // Release the context
    HMAC_CTX_free(ctx);
    return;
  }

  // Return pointer to the context
  Dart_SetIntegerReturnValue(args, (int64_t)ctx);
}

/// Signature: (int ctx, Uint8List data) -> Null | String
void hmac_write(Dart_NativeArguments args) {
  ARGUMENT_COUNT_OR_RETURN(2);
  DEFINE_INT_ARG_OR_RETURN(0, _ctx);
  HMAC_CTX* ctx = (HMAC_CTX*)_ctx;

  DEFINE_UINT8LIST_ARG_OR_RETURN(1, dataHandle);
  ACCESS_UINT8LIST_OR_RETURN(dataHandle, data, length);

  if (HMAC_Update(ctx, data, length) != 1) {
    SET_RETURN_VALUE_TO_BORINGSSL_ERROR_STRING();
    return;
  }

  Dart_SetReturnValue(args, Dart_Null());
}

/// Signature: (int ctx) -> Uint8List | String
void hmac_result(Dart_NativeArguments args) {
  ARGUMENT_COUNT_OR_RETURN(1);
  DEFINE_INT_ARG_OR_RETURN(0, _ctx);
  HMAC_CTX* ctx = (HMAC_CTX*)_ctx;

  // Get the digest size
  size_t result_size = HMAC_size(ctx);

  // Allocate an Uint8List for the result
  auto dataHandle = Dart_NewTypedData(Dart_TypedData_kUint8, result_size);
  NOT_ERROR_OR_RETURN(dataHandle);
  ACCESS_UINT8LIST_OR_RETURN(dataHandle, data, length);

  // Extract the final result
  if (HMAC_Final(ctx, data, nullptr) != 1) {
    SET_RETURN_VALUE_TO_BORINGSSL_ERROR_STRING();
    return;
  }

  Dart_SetReturnValue(args, dataHandle);
}

/// Signature: (int ctx) -> Null | String
void hmac_destroy(Dart_NativeArguments args) {
  ARGUMENT_COUNT_OR_RETURN(1);
  DEFINE_INT_ARG_OR_RETURN(0, _ctx);
  HMAC_CTX* ctx = (HMAC_CTX*)_ctx;

  HMAC_CTX_free(ctx);

  Dart_SetReturnValue(args, Dart_Null());
}
