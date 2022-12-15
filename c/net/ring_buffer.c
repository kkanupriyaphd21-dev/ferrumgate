#include "../include/ferrumgate.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <pthread.h>
#include <stdbool.h>

/* Lock-free single-producer single-consumer ring buffer */
typedef struct {
    uint8_t*  buf;
    size_t    capacity;
    size_t    mask;
    size_t    head; /* producer writes here */
    size_t    tail; /* consumer reads here */
} FgRingBuffer;

static bool is_power_of_two(size_t n) {
    return n && !(n & (n-1));
}

FgRingBuffer* fg_ring_create(size_t capacity) {
    if (!is_power_of_two(capacity)) return NULL;
    FgRingBuffer* rb = calloc(1, sizeof(FgRingBuffer));
    if (!rb) return NULL;
    rb->buf = malloc(capacity);
    if (!rb->buf) { free(rb); return NULL; }
    rb->capacity = capacity;
    rb->mask     = capacity - 1;
    return rb;
}

void fg_ring_free(FgRingBuffer* rb) {
    if (!rb) return;
    free(rb->buf);
    free(rb);
}

size_t fg_ring_write_avail(const FgRingBuffer* rb) {
    return rb->capacity - (rb->head - rb->tail);
}

size_t fg_ring_read_avail(const FgRingBuffer* rb) {
    return rb->head - rb->tail;
}

ssize_t fg_ring_write(FgRingBuffer* rb, const uint8_t* data, size_t len) {
    if (fg_ring_write_avail(rb) < len) return 0;

    size_t head   = rb->head & rb->mask;
    size_t to_end = rb->capacity - head;

    if (len <= to_end) {
        memcpy(rb->buf + head, data, len);
    } else {
        memcpy(rb->buf + head, data, to_end);
        memcpy(rb->buf,        data + to_end, len - to_end);
    }

    __sync_fetch_and_add(&rb->head, len);
    return (ssize_t)len;
}

ssize_t fg_ring_read(FgRingBuffer* rb, uint8_t* out, size_t len) {
    size_t avail = fg_ring_read_avail(rb);
    if (avail == 0) return 0;
    if (len > avail) len = avail;

    size_t tail   = rb->tail & rb->mask;
    size_t to_end = rb->capacity - tail;

    if (len <= to_end) {
        memcpy(out, rb->buf + tail, len);
    } else {
        memcpy(out,           rb->buf + tail, to_end);
        memcpy(out + to_end,  rb->buf,        len - to_end);
    }

    __sync_fetch_and_add(&rb->tail, len);
    return (ssize_t)len;
}

/* Peek without consuming */
ssize_t fg_ring_peek(const FgRingBuffer* rb, uint8_t* out, size_t len) {
    size_t avail = fg_ring_read_avail(rb);
    if (avail == 0) return 0;
    if (len > avail) len = avail;

    size_t tail   = rb->tail & rb->mask;
    size_t to_end = rb->capacity - tail;

    if (len <= to_end) {
        memcpy(out, rb->buf + tail, len);
    } else {
        memcpy(out,           rb->buf + tail, to_end);
        memcpy(out + to_end,  rb->buf,        len - to_end);
    }
    return (ssize_t)len;
}

void fg_ring_drain(FgRingBuffer* rb, size_t n) {
    size_t avail = fg_ring_read_avail(rb);
    if (n > avail) n = avail;
    __sync_fetch_and_add(&rb->tail, n);
}

void fg_ring_reset(FgRingBuffer* rb) {
    if (!rb) return;
    rb->head = rb->tail = 0;
}
