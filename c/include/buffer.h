#pragma once
#include "ferrumgate.h"
#include <sys/types.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct FgRingBuffer FgRingBuffer;

FgRingBuffer* fg_ring_create(size_t capacity);
void          fg_ring_free(FgRingBuffer* rb);
size_t        fg_ring_write_avail(const FgRingBuffer* rb);
size_t        fg_ring_read_avail(const FgRingBuffer* rb);
ssize_t       fg_ring_write(FgRingBuffer* rb, const uint8_t* data, size_t len);
ssize_t       fg_ring_read(FgRingBuffer* rb, uint8_t* out, size_t len);
ssize_t       fg_ring_peek(const FgRingBuffer* rb, uint8_t* out, size_t len);
void          fg_ring_drain(FgRingBuffer* rb, size_t n);
void          fg_ring_reset(FgRingBuffer* rb);

#ifdef __cplusplus
}
#endif
