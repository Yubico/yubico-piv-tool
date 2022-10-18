#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "harness.h"

harness_state_t harness_state;

int CustomFuzzerTestOneInput(test_case_t *test_case) {
    ykpiv_state *state;

    printf("kek what\n");

    memset(&harness_state, 0, sizeof(harness_state));
    harness_state.test_case = test_case;

    ykpiv_init(&state, 0);
    state->protocol = test_case->state_protocol;

    ykpiv_connect(state, "fuzz_reader");

    ykpiv_done_with_external_card(state);

    return 0;
}
