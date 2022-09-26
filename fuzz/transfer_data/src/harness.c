#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <internal.h>
#include <ykpiv.h>

const SCARD_IO_REQUEST g_rgSCardT0Pci = { SCARD_PROTOCOL_T0, sizeof(SCARD_IO_REQUEST) };
const SCARD_IO_REQUEST g_rgSCardT1Pci = { SCARD_PROTOCOL_T1, sizeof(SCARD_IO_REQUEST) };
const SCARD_IO_REQUEST g_rgSCardRawPci = { SCARD_PROTOCOL_RAW, sizeof(SCARD_IO_REQUEST) };

typedef struct {
    uint32_t state_protocol;
    uint32_t in_len;
    uint32_t out_len;
    uint8_t *in_data;
    uint8_t *out_data;
} test_case_t;

static test_case_t *g_test_case = NULL;
static int out_data_offset = 0;

LONG SCardTransmit(
    SCARDHANDLE hCard,
    const SCARD_IO_REQUEST *pioSendPci,
    LPCBYTE pbSendBuffer,
    DWORD cbSendLength,
    SCARD_IO_REQUEST *pioRecvPci,
    LPBYTE pbRecvBuffer,
    LPDWORD pcbRecvLength) {

    uint32_t test_case_remaining = g_test_case->out_len - out_data_offset;
    if (*pcbRecvLength > test_case_remaining) {
        *pcbRecvLength = test_case_remaining;
    }

    if (g_test_case->out_data != NULL) {
        memcpy(pbRecvBuffer, &g_test_case->out_data[out_data_offset], *pcbRecvLength);
    } else {
        memset(pbRecvBuffer, 0, *pcbRecvLength);
    }
    out_data_offset += *pcbRecvLength;

    return SCARD_S_SUCCESS;
}

int CustomFuzzerTestOneInput(test_case_t *test_case) {
    uint8_t templ[] = {0xde, 0xad, 0xbe, 0xef};
    ykpiv_state state;
    uint8_t *out = calloc(1, test_case->out_len);
    int sw = 0;

    g_test_case = test_case;
    out_data_offset = 0;

    memset(&state, 0, sizeof(state));
    state.protocol = test_case->state_protocol;

    ykpiv_transfer_data(
        &state,
        templ,
        test_case->in_data,
        test_case->in_len,
        out,
        &test_case->out_len,
        &sw
    );

    free(out);

    return 0;
}
