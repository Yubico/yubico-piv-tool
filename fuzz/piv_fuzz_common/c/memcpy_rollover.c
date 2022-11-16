#include "memcpy_rollover.h"
#include <stdio.h>

void memcpy_rollover(uint8_t *dst, uint8_t *src, size_t dst_len, size_t src_len, size_t *src_offset) {
    size_t amount = 0;
    size_t dst_offset = 0;

    if (src_len == 0 || dst_len == 0) {
        return;
    }

    while (dst_offset < dst_len) {
        if (dst_len - dst_offset > src_len - *src_offset) {
            amount = src_len - *src_offset;
        } else {
            amount = dst_len - dst_offset;
        }
        memcpy(&dst[dst_offset], &src[*src_offset], amount);
        dst_offset += amount;
        *src_offset = (*src_offset + amount) % src_len;
    }
}
