#ifndef DEBUG_H
#define DEBUG_H

#define YKCS11_DBG    1  // General debug, must be either 1 or 0
#define YKCS11_DINOUT 0  // Function in/out debug, must be either 1 or 0

#define D(x) do {                                                     \
    printf ("debug: %s:%d (%s): ", __FILE__, __LINE__, __FUNCTION__); \
    printf x;                                                         \
    printf ("\n");                                                    \
  } while (0)

#if YKCS11_DBG
#include <stdio.h>
#define DBG(x) D(x);
#else
#define DBG(x)
#endif

#if YKCS11_DINOUT
#define DIN D(("In"));
#define DOUT D(("Out"));
#else
#define DIN
#define DOUT
#endif

#endif
