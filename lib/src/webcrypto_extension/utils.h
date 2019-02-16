#ifndef WEBCRYPTO_EXTENSION_UTILS_H
#define WEBCRYPTO_EXTENSION_UTILS_H

#include <include/dart_api.h>
#include <include/dart_native_api.h>
#include <openssl/err.h>

void compare(Dart_NativeArguments args);

/// Create a Dart scope.
class DartScope {
 public:
  DartScope() { Dart_EnterScope(); }
  ~DartScope() { Dart_ExitScope(); }

 private:
  // Private copy constructor and assignment operator.
  DartScope(DartScope const &);
  DartScope &operator=(DartScope const &);
};

/// Access TypedData reasonably safely.
class TypedDataScope {
 public:
  TypedDataScope(Dart_Handle handle) {
    this->handle = handle;
    error = Dart_TypedDataAcquireData(handle, &type, &data, &length);
  }
  ~TypedDataScope() { Dart_TypedDataReleaseData(handle); }

  Dart_Handle error;
  Dart_Handle handle;
  Dart_TypedData_Type type;
  intptr_t length;
  void *data;
  bool isError() { return Dart_IsError(error); }

 private:
  // Private copy constructor and assignment operator.
  TypedDataScope(TypedDataScope const &);
  TypedDataScope &operator=(TypedDataScope const &);
};

#define ARGUMENT_COUNT_OR_RETURN(count)                         \
  do {                                                          \
    if (Dart_GetNativeArgumentCount(args) != count) {           \
      auto err = Dart_NewApiError("wrong number of arguments"); \
      Dart_SetReturnValue(args, err);                           \
      return;                                                   \
    }                                                           \
  } while (0)

#define DEFINE_INT_ARG_OR_RETURN(index, name)                    \
  int64_t name;                                                  \
  do {                                                           \
    auto ok = Dart_GetNativeIntegerArgument(args, index, &name); \
    if (Dart_IsError(ok)) {                                      \
      Dart_SetReturnValue(args, ok);                             \
      return;                                                    \
    }                                                            \
  } while (0)

#define DEFINE_UINT8LIST_ARG_OR_RETURN(index, handle)                       \
  Dart_Handle handle = Dart_GetNativeArgument(args, index);                 \
  do {                                                                      \
    if (Dart_IsError(handle)) {                                             \
      Dart_SetReturnValue(args, handle);                                    \
      return;                                                               \
    }                                                                       \
    if (!Dart_IsTypedData(handle)) {                                        \
      Dart_SetReturnValue(args, Dart_NewApiError("expected an Uint8List")); \
      return;                                                               \
    }                                                                       \
  } while (0)

#define DEFINE_OBJECT_ARG_OR_RETURN(index, handle)                       \
  Dart_Handle handle = Dart_GetNativeArgument(args, index);              \
  do {                                                                   \
    if (Dart_IsError(handle)) {                                          \
      Dart_SetReturnValue(args, handle);                                 \
      return;                                                            \
    }                                                                    \
    if (Dart_IsNull(handle)) {                                           \
      Dart_SetReturnValue(args, Dart_NewApiError("expected an Object")); \
      return;                                                            \
    }                                                                    \
  } while (0)

#define ACCESS_UINT8LIST_OR_RETURN(handle, name, length)                    \
  uint8_t *name;                                                            \
  size_t length;                                                            \
  TypedDataScope _##name##_scope(handle);                                   \
  do {                                                                      \
    if (_##name##_scope.isError()) {                                        \
      Dart_SetReturnValue(args, _##name##_scope.error);                     \
      return;                                                               \
    }                                                                       \
    if (_##name##_scope.type != Dart_TypedData_kUint8) {                    \
      Dart_SetReturnValue(args, Dart_NewApiError("expected an Uint8List")); \
      return;                                                               \
    }                                                                       \
    name = (uint8_t *)_##name##_scope.data;                                 \
    length = (size_t)_##name##_scope.len##gth;                              \
  } while (0)

#define NOT_ERROR_OR_RETURN(handle)      \
  do {                                   \
    if (Dart_IsError(handle)) {          \
      Dart_SetReturnValue(args, handle); \
      return;                            \
    }                                    \
  } while (0)

#define RETURN_API_ERROR(message)                         \
  do {                                                    \
    Dart_SetReturnValue(args, Dart_NewApiError(message)); \
    return;                                               \
  } while (0)

#define SET_RETURN_VALUE_TO_BORINGSSL_ERROR_STRING()                       \
  do {                                                                     \
    auto error = ERR_get_error();                                          \
    Dart_Handle message;                                                   \
    if (error != 0) {                                                      \
      message = Dart_NewStringFromCString(ERR_reason_error_string(error)); \
    } else {                                                               \
      message = Dart_NewStringFromCString("unknown internal error");       \
    }                                                                      \
    ERR_clear_error();                                                     \
    Dart_SetReturnValue(args, message);                                    \
  } while (0)

#define IGNORE_BORINGSSL_ERROR ERR_clear_error()

#endif /* WEBCRYPTO_EXTENSION_UTILS_H */