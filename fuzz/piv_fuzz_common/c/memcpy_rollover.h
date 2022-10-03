#pragma once

#include <stdint.h>
#include <string.h>

void memcpy_rollover(uint8_t *dst, uint8_t *src, size_t dst_len, size_t src_len, size_t *src_offset);
