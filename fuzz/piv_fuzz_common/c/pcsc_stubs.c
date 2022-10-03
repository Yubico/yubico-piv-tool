#include <string.h>

#include <internal.h>
#include <ykpiv.h>

#include <harness.h>
#include "memcpy_rollover.h"

const SCARD_IO_REQUEST g_rgSCardT0Pci = { SCARD_PROTOCOL_T0, sizeof(SCARD_IO_REQUEST) };
const SCARD_IO_REQUEST g_rgSCardT1Pci = { SCARD_PROTOCOL_T1, sizeof(SCARD_IO_REQUEST) };
const SCARD_IO_REQUEST g_rgSCardRawPci = { SCARD_PROTOCOL_RAW, sizeof(SCARD_IO_REQUEST) };

LONG SCardTransmit(
    SCARDHANDLE hCard,
    const SCARD_IO_REQUEST *pioSendPci,
    LPCBYTE pbSendBuffer,
    DWORD cbSendLength,
    SCARD_IO_REQUEST *pioRecvPci,
    LPBYTE pbRecvBuffer,
    LPDWORD pcbRecvLength) {

    if (harness_state.test_case->out_data != NULL && harness_state.test_case->out_len > 0) {
        memcpy_rollover(
            pbRecvBuffer,
            harness_state.test_case->out_data,
            *pcbRecvLength,
            harness_state.test_case->out_len,
            &harness_state.out_data_offset
        );
    } else {
        memset(pbRecvBuffer, 0, *pcbRecvLength);
    }

    return SCARD_S_SUCCESS;
}
