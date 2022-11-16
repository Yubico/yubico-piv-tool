#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "harness.h"

harness_state_t harness_state;

int CustomFuzzerTestOneInput(test_case_t *test_case) {
    uint8_t templ[] = {0xde, 0xad, 0xbe, 0xef};
    ykpiv_state *state;
    uint8_t *out = calloc(1, test_case->pcsc_data_len);
    size_t out_len = test_case->pcsc_data_len;
    int sw = 0;

    memset(&harness_state, 0, sizeof(harness_state));
    harness_state.test_case = test_case;

    ykpiv_init(&state, 0);
    state->protocol = test_case->state_protocol;

    ykpiv_transfer_data(
        state,
        templ,
        test_case->in_data,
        test_case->in_len,
        out,
        &out_len,
        &sw
    );

    ykpiv_done_with_external_card(state);
    free(out);

    return 0;
}
