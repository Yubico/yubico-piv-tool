#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "harness.h"

harness_state_t harness_state;

int CustomFuzzerTestOneInput(test_case_t *test_case) {
    uint8_t key[] = {
        // this is supposed to be a triple des key (24 bytes long)
        0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
        0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
        0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef
    };
    ykpiv_state *state;
    int sw = 0;

    memset(&harness_state, 0, sizeof(harness_state));
    harness_state.test_case = test_case;

    ykpiv_init(&state, 0);
    state->protocol = test_case->state_protocol;

    ykpiv_authenticate2(state, key, sizeof(key));

    ykpiv_done_with_external_card(state);

    return 0;
}
