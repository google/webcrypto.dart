#include "openssl/bytestring.h"
#include "openssl/evp.h"

#include "utils.h"

// import Spki
// EVP_parse_public_key
// Apply: RSA_check_key

/// Signature: (keyhandle, keyData) -> Null | String
void rsassa_importSpkiKey(Dart_NativeArguments args) {
  ARGUMENT_COUNT_OR_RETURN(2);
  DEFINE_OBJECT_ARG_OR_RETURN(1, keyHandle);
  DEFINE_UINT8LIST_ARG_OR_RETURN(1, keyDataHandle);

  ACCESS_UINT8LIST_OR_RETURN(keyDataHandle, keyData, keyDataLength);

  // Parse key
  CBS cbs;
  CBS_init(&cbs, keyData, keyDataLength);
  EVP_PKEY* pkey = EVP_parse_public_key(&cbs);
  if (pkey == nullptr) {
    SET_RETURN_VALUE_TO_BORINGSSL_ERROR_STRING();
    return;
  }

  // Check the imported key type
  if (EVP_PKEY_id(pkey) != EVP_PKEY_RSA) {
    Dart_SetReturnValue(args, Dart_NewStringFromCString("incorrect key type"));
    EVP_PKEY_free(pkey);
  }
  RSA* rsa = EVP_PKEY_get0_RSA(pkey);
  if (rsa == nullptr) {
    Dart_SetReturnValue(args, Dart_NewStringFromCString("incorrect key type"));
    EVP_PKEY_free(pkey);
  }
  if (RSA_check_key(rsa) != 1) {
    Dart_SetReturnValue(args, Dart_NewStringFromCString("invalid key"));
    EVP_PKEY_free(pkey);
  }
  if (EVP_PKEY_missing_parameters(pkey) != 0) {
    Dart_SetReturnValue(args, Dart_NewStringFromCString("invalid parameters"));
    EVP_PKEY_free(pkey);
  }

  // The VM would like an estimate of the size, we'll just make it 16 times
  // the signature, as a nice estimate.
  int size = EVP_PKEY_size(pkey) * 16;

  EVP_PKEY_free(pkey);

  // Dart_NewWeakPersistentHandle()
}

/// Signature: (int hashIdentifier, Uint8List keyData) -> int | String
void rsassa_verify_create(Dart_NativeArguments args) { return; }

/// Signature: (int ctx, Uint8List data) -> Null | String
void rsassa_verify_write(Dart_NativeArguments args) { return; }

/// Signature: (int ctx) -> Uint8List | String
void rsassa_verify_result(Dart_NativeArguments args) { return; }

/// Signature: (int ctx) -> Null | String
void rsassa_verify_destroy(Dart_NativeArguments args) { return; }

// import pkcs8
// EVP_parse_private_key
// Apply: RSA_check_key
