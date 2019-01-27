#ifndef WEBCRYPTO_EXTENSION_DIGEST_H
#define WEBCRYPTO_EXTENSION_DIGEST_H

#include <include/dart_api.h>
#include <include/dart_native_api.h>
#include <openssl/digest.h>

void digest_create(Dart_NativeArguments args);
void digest_write(Dart_NativeArguments args);
void digest_result(Dart_NativeArguments args);
void digest_destroy(Dart_NativeArguments args);

const EVP_MD* hashIdentifierToAlgorithm(int hashIdentifier);

#endif /* WEBCRYPTO_EXTENSION_DIGEST_H */