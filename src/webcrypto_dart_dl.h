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

#ifndef FINALIZER_H
#define FINALIZER_H

#include <stddef.h>
#include "include/dart_api_dl.h"

// Initialize Dart API with dynamic linking.
//
// Must be called with `NativeApi.initializeApiDLData` from `dart:ffi`, before
// using other functions.
//
// Returns 1 on success.
int webcrypto_dart_dl_initialize(void* initialize_api_dl_data);

// Function pointer for de-allocation of a pointer, when attaching a finalizer
// using webcrypto_attach_finalizer.
typedef void (*webcrypto_finalizer_t)(void*);

// Attach a finalizer for pointer to object, such that `finalizer(pointer)` will
// be called when `object` is collected by the Dart garbage collector.
//
// The external_allocation_size is used by the Dart garbage collector as a hint
// about the size of the external allocation.
//
// Returns 1 on success.
int webcrypto_dart_dl_attach_finalizer(Dart_Handle object,
                                       void* pointer,
                                       webcrypto_finalizer_t finalizer,
                                       intptr_t external_allocation_size);

#endif  // FINALIZER_H
