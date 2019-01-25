#ifndef WEBCRYPTO_EXTENSION_UTILS_H
#define WEBCRYPTO_EXTENSION_UTILS_H

#include <include/dart_api.h>
#include <include/dart_native_api.h>

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
class TypedData {
 public:
  TypedData(Dart_Handle handle) {
    this->handle = handle;
    error = Dart_TypedDataAcquireData(handle, &type, &data, &length);
  }
  ~TypedData() { Dart_TypedDataReleaseData(handle); }

  Dart_Handle error;
  Dart_Handle handle;
  Dart_TypedData_Type type;
  intptr_t length;
  void *data;
  bool isError() { return Dart_IsError(error); }

 private:
  // Private copy constructor and assignment operator.
  TypedData(TypedData const &);
  TypedData &operator=(TypedData const &);
};

#endif /* WEBCRYPTO_EXTENSION_UTILS_H */