#pragma once

#include <internal.h>
#include <ykpiv.h>

typedef struct {
    uint32_t state_protocol;

    uint32_t pcsc_data_len;
    uint32_t readers_len;

    uint32_t plaintext_len;

    uint8_t *pcsc_data;
    uint8_t *readers;

    uint8_t *plaintext;
} test_case_t;

typedef struct {
    test_case_t *test_case;
    size_t pcsc_data_offset;
    size_t plaintext_offset;
} harness_state_t;

extern harness_state_t harness_state;
