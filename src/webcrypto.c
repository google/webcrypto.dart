/*
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <openssl/bytestring.h>
#include <openssl/evp.h>

#include "webcrypto.h"

WEBCRYPTO_EXPORT size_t webcrypto_get_CBB_size(void) {
  return sizeof(CBB);
}

// NativeFinalizer requires a raw native function pointer. ffigen ignores
// symbol-address entries for functions emitted as direct @Native bindings, so
// expose this one address explicitly.
WEBCRYPTO_EXPORT void* webcrypto_get_EVP_PKEY_free_address(void) {
  return (void*)&EVP_PKEY_free;
}
