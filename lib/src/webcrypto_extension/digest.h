#ifndef WEBCRYPTO_EXTENSION_DIGEST_H
#define WEBCRYPTO_EXTENSION_DIGEST_H

#include <include/dart_api.h>
#include <include/dart_native_api.h>

void SystemRand(Dart_NativeArguments arguments);

void digest_create(Dart_NativeArguments args);
void digest_write(Dart_NativeArguments args);
void digest_result(Dart_NativeArguments args);
void digest_destroy(Dart_NativeArguments args);

#endif /* WEBCRYPTO_EXTENSION_DIGEST_H */