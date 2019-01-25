#include <openssl/digest.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>

#include "digest.h"
#include "utils.h"

Dart_Handle HandleError(Dart_Handle handle) {
  if (Dart_IsError(handle)) {
    Dart_PropagateError(handle);
  }
  return handle;
}

void computeDigest(Dart_NativeArguments args) {
  auto algorithm = EVP_sha1();
  EVP_MD_CTX ctx;

  // i = Dart_GetNativeArgumentCount(args);
  // handle = Dart_GetNativeArgument(args, 0)

  if (EVP_DigestInit(&ctx, algorithm) != 1) {
    ERR_clear_error();
    // TODO: return operation error
  }

  if (EVP_DigestUpdate(&ctx, nullptr, 0) != 1) {
    ERR_clear_error();
    // TODO: return operation error
  }

  if (EVP_MD_CTX_cleanup(&ctx) != 1) {
    ERR_clear_error();
    // TODO: return operation error
  }

  Dart_Handle result = HandleError(Dart_NewInteger(rand()));
  Dart_SetReturnValue(args, result);
}

void SystemRand(Dart_NativeArguments arguments) {
  Dart_Handle result = HandleError(Dart_NewInteger(rand()));
  Dart_SetReturnValue(arguments, result);
}
