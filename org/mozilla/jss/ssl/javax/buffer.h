#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#pragma once

typedef struct {
    uint8_t *contents;
    size_t capacity;

    size_t write_pos;
    size_t read_pos;
} j_buffer;

j_buffer *jb_alloc(size_t length);

size_t jb_capacity(j_buffer *buf);
bool jb_can_read(j_buffer *buf);
bool jb_can_write(j_buffer *buf);

int jb_put(j_buffer *buf, uint8_t byte);
size_t jb_write(j_buffer *buf, uint8_t *input, size_t input_size);

int jb_get(j_buffer *buf);
size_t jb_read(j_buffer *buf, uint8_t *output, size_t output_size);

void jb_free(j_buffer *buf);
