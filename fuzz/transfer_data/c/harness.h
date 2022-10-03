#pragma once

#include <internal.h>
#include <ykpiv.h>

typedef struct {
    uint32_t state_protocol;
    uint32_t in_len;
    uint32_t out_len;
    uint8_t *in_data;
    uint8_t *out_data;
} test_case_t;

typedef struct {
    test_case_t *test_case;
    size_t out_data_offset;
    size_t plaintext_offset;
} harness_state_t;

extern harness_state_t harness_state;
