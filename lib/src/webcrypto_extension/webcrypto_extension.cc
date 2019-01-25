#include <stdio.h>
#include <string.h>

#include "digest.h"
#include "random.h"
#include "utils.h"

struct FunctionEntry {
  const char *name;
  Dart_NativeFunction function;
};

FunctionEntry functions[] = {
    {"SystemRand", SystemRand},
    {"getRandomValues", getRandomValues},
    {nullptr, nullptr},
};

// https://www.dartlang.org/articles/server/native-extensions

Dart_NativeFunction resolver(Dart_Handle name, int argc,
                             bool *auto_setup_scope) {
  // Input sanity checks
  if (!Dart_IsString(name)) {
    return nullptr;
  }
  if (auto_setup_scope == nullptr) {
    return nullptr;
  }

  DartScope scope;

  // Get the name
  const char *cname;
  Dart_Handle handle = Dart_StringToCString(name, &cname);
  if (Dart_IsError(handle)) {
    // This exits the current function (ie. it never returns)
    Dart_PropagateError(handle);
  }

  // Find function if possible
  Dart_NativeFunction result = nullptr;
  for (int i = 0; functions[i].name != nullptr; ++i) {
    if (strcmp(functions[i].name, cname) == 0) {
      *auto_setup_scope = true;
      result = functions[i].function;
      break;
    }
  }

  return result;
}

DART_EXPORT Dart_Handle webcrypto_extension_Init(Dart_Handle parent) {
  if (Dart_IsError(parent)) {
    return parent;
  }
  // Set the resolver for the library
  Dart_Handle ret = Dart_SetNativeResolver(parent, resolver, nullptr);
  if (Dart_IsError(ret)) {
    return ret;
  }
  return Dart_Null();
}
