#include "webcrypto_dart_dl.h"

#include <openssl/mem.h>

// See webcrypto_dart_dl.h
int webcrypto_dart_dl_initialize(void* initialize_api_dl_data) {
  if (Dart_InitializeApiDL(initialize_api_dl_data) != 0) {
    return -1;
  }
  // Check symbols used are present
  if (Dart_NewFinalizableHandle_DL == NULL) {
    return -1;
  }
  return 1;
}

// peer attached
typedef struct _finalizable_pointer {
  void* pointer;
  webcrypto_finalizer_t finalizer;
} _finalizable_pointer;

// Callback from Dart_NewFinalizableHandle_DL when we have attached a finalizer
// to some Dart object.
void _webcrypto_finalizer_callback(void* isolate_callback_data, void* peer) {
  _finalizable_pointer* p = (_finalizable_pointer*)peer;

  // If pointer or finalizer is NULL, we've already deallocated, we can assert
  // that this doesn't happen.
  assert(p->pointer != NULL);
  assert(p->finalizer != NULL);
  if (p->pointer == NULL || p->finalizer == NULL) {
    // Abort if this happens in production where we have no asserts.
    return;
  }

  // Call the finalizer
  p->finalizer(p->pointer);

  // Ensure that assertions will trigger upon double deallocation.
  p->pointer = NULL;
  p->finalizer = NULL;

  // Free the peer
  OPENSSL_free(p);
}

// See webcrypto_dart_dl.h
int webcrypto_dart_dl_attach_finalizer(Dart_Handle object,
                                       void* pointer,
                                       webcrypto_finalizer_t finalizer,
                                       intptr_t external_allocation_size) {
  // Create a _finalizable_pointer to be attached as peer.
  _finalizable_pointer* peer = OPENSSL_malloc(sizeof(_finalizable_pointer));
  peer->finalizer = finalizer;
  peer->pointer = pointer;

  // Attaced peer and _webcrypto_finalizer_callback
  Dart_FinalizableHandle handle;
  // NOTE: we have check the availability of Dart_NewFinalizableHandle_DL in
  //       webcrypto_dart_dl_initialize.
  handle = Dart_NewFinalizableHandle_DL(object, (void*)peer,
                                        external_allocation_size,
                                        &_webcrypto_finalizer_callback);

  // Check if the operation was successful
  if (handle == NULL) {
    OPENSSL_free(peer);
    return -1;
  }
  return 1;
}
