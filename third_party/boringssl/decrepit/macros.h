/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_HEADER_DECREPIT_MACROS_H
#define OPENSSL_HEADER_DECREPIT_MACROS_H

#include "../crypto/internal.h"


// NOTE - c is not incremented as per n2l
#define n2ln(c, l1, l2, n)                  \
  {                                         \
    c += n;                                 \
    l1 = l2 = 0;                            \
    switch (n) {                            \
      case 8:                               \
        l2 = ((uint32_t)(*(--(c))));        \
        [[fallthrough]];                    \
      case 7:                               \
        l2 |= ((uint32_t)(*(--(c)))) << 8;  \
        [[fallthrough]];                    \
      case 6:                               \
        l2 |= ((uint32_t)(*(--(c)))) << 16; \
        [[fallthrough]];                    \
      case 5:                               \
        l2 |= ((uint32_t)(*(--(c)))) << 24; \
        [[fallthrough]];                    \
      case 4:                               \
        l1 = ((uint32_t)(*(--(c))));        \
        [[fallthrough]];                    \
      case 3:                               \
        l1 |= ((uint32_t)(*(--(c)))) << 8;  \
        [[fallthrough]];                    \
      case 2:                               \
        l1 |= ((uint32_t)(*(--(c)))) << 16; \
        [[fallthrough]];                    \
      case 1:                               \
        l1 |= ((uint32_t)(*(--(c)))) << 24; \
    }                                       \
  }

// NOTE - c is not incremented as per l2n
#define l2nn(l1, l2, c, n)                               \
  {                                                      \
    c += n;                                              \
    switch (n) {                                         \
      case 8:                                            \
        *(--(c)) = (unsigned char)(((l2)) & 0xff);       \
        [[fallthrough]];                                 \
      case 7:                                            \
        *(--(c)) = (unsigned char)(((l2) >> 8) & 0xff);  \
        [[fallthrough]];                                 \
      case 6:                                            \
        *(--(c)) = (unsigned char)(((l2) >> 16) & 0xff); \
        [[fallthrough]];                                 \
      case 5:                                            \
        *(--(c)) = (unsigned char)(((l2) >> 24) & 0xff); \
        [[fallthrough]];                                 \
      case 4:                                            \
        *(--(c)) = (unsigned char)(((l1)) & 0xff);       \
        [[fallthrough]];                                 \
      case 3:                                            \
        *(--(c)) = (unsigned char)(((l1) >> 8) & 0xff);  \
        [[fallthrough]];                                 \
      case 2:                                            \
        *(--(c)) = (unsigned char)(((l1) >> 16) & 0xff); \
        [[fallthrough]];                                 \
      case 1:                                            \
        *(--(c)) = (unsigned char)(((l1) >> 24) & 0xff); \
    }                                                    \
  }

#define l2n(l, c)                                   \
  (*((c)++) = (unsigned char)(((l) >> 24L) & 0xff), \
   *((c)++) = (unsigned char)(((l) >> 16L) & 0xff), \
   *((c)++) = (unsigned char)(((l) >> 8L) & 0xff),  \
   *((c)++) = (unsigned char)(((l)) & 0xff))

#define n2l(c, l)                                                         \
  (l = ((uint32_t)(*((c)++))) << 24L, l |= ((uint32_t)(*((c)++))) << 16L, \
   l |= ((uint32_t)(*((c)++))) << 8L, l |= ((uint32_t)(*((c)++))))


#endif  // OPENSSL_HEADER_DECREPIT_MACROS_H
