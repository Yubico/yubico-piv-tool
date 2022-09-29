#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "harness.h"

harness_state_t harness_state;

int CustomFuzzerTestOneInput(test_case_t *test_case) {
    uint8_t key[] = {
        0xde, 0xad, 0xbe, 0xef,
        0xde, 0xad, 0xbe, 0xef,
        0xde, 0xad, 0xbe, 0xef,
        0xde, 0xad, 0xbe, 0xef
    };

    ykpiv_state state;
    uint8_t *out = calloc(1, test_case->out_len);
    int sw = 0;

    memset(&harness_state, 0, sizeof(harness_state));
    harness_state.test_case = test_case;

    memset(&state, 0, sizeof(state));
    state.protocol = test_case->state_protocol;

    ykpiv_authenticate2(&state, key, sizeof(key));

    free(out);

    return 0;
}
