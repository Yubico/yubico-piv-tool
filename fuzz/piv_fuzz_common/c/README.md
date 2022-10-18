These stubs expect at a minimum the following symbols with struct types containing the following fields (depending on which stubs you require):

```c
#pragma once

#include <internal.h>
#include <ykpiv.h>

typedef struct {
    uint32_t state_protocol;
    uint32_t pcsc_data_len;     // required for pcsc stubs
    uint32_t plaintext_len;     // required for openssl stubs
    uint8_t *pcsc_data;         // required for pcsc stubs
    uint8_t *plaintext;         // required for openssl stubs
} test_case_t;

typedef struct {
    test_case_t *test_case;
    size_t pcsc_data_offset;    // required for pcsc stubs
    size_t plaintext_offset;    // required for openssl stubs
} harness_state_t;

extern harness_state_t harness_state;
```

The order of the fields within each structure is not relevant.
