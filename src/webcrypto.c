#include <stdint.h>

#include "symbols.h"

// Macro for annotating all functions to be exported
#define WEBCRYPTO_EXPORT                 \
  __attribute__((visibility("default"))) \
      __attribute__((used))

// Function to lookup BoringSSL symbols based on index in the Sym enum.
// See src/symbols.yaml for details.
WEBCRYPTO_EXPORT void *webcrypto_lookup_symbol(int32_t index)
{
  return _webcrypto_symbol_table[index];
}
