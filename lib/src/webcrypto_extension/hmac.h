#ifndef WEBCRYPTO_EXTENSION_HMAC_H
#define WEBCRYPTO_EXTENSION_HMAC_H

#include <include/dart_api.h>
#include <include/dart_native_api.h>

void hmac_create(Dart_NativeArguments args);
void hmac_write(Dart_NativeArguments args);
void hmac_result(Dart_NativeArguments args);
void hmac_destroy(Dart_NativeArguments args);

#endif /* WEBCRYPTO_EXTENSION_HMAC_H */