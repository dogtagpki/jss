#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#pragma once

/*
 * Opaque structure for buffers. Subject to change at any time.
 *
 * A j_buffer is a circular ring buffer creating a FIFO queue of bytes.
 */
typedef struct {
    /* Contents of the buffer. */
    uint8_t *contents;

    /* Capacity is used as a sentinel value; when write_pos == capacity, can't
     * write. */
    size_t capacity;

    /* Next position to write to, else capacity if unable to write. */
    size_t write_pos;

    /* Next position to read from, else capacity if unable to read. */
    size_t read_pos;
} j_buffer;

/*
 * Create a new buffer; must be freed with jb_free. The length parameter is
 * the number of uint8_t elements the new buffer can store.
 */
j_buffer *jb_alloc(size_t length);

/* Get the original capacity (i.e., when empty) of the specified buffer. */
size_t jb_capacity(j_buffer *buf);

/* Whether or not the buffer can be read from. */
bool jb_can_read(j_buffer *buf);

/* Number of bytes which can be read. */
size_t jb_read_capacity(j_buffer *buf);

/* Whether or not the buffer can be written to. */
bool jb_can_write(j_buffer *buf);

/* Number of bytes which can be written. */
size_t jb_write_capacity(j_buffer *buf);

/*
 * Store a character into the buffer. Returns the character if stored,
 * else EOF if unable to store the character (because the buffer is full).
 * When not EOF, can safely be casted to a uint8_t.
 */
int jb_put(j_buffer *buf, uint8_t byte);

/*
 * Store many characters into the buffer from an array of characters. Returns
 * the number of characters written into the buffer; max of input_size. This
 * is zero when the buffer is already full.
 */
size_t jb_write(j_buffer *buf, const uint8_t *input, size_t input_size);

/*
 * Get the next character from the buffer or EOF if the buffer is empty. If
 * not EOF, can safely be casted to uint8_t.
 */
int jb_get(j_buffer *buf);

/*
 * Read several characters from the buffer in the order they were written. The
 * characters are placed in output and up to output_size characters are read.
 * Returns the number of characters read; zero if the buffer was empty.
 */
size_t jb_read(j_buffer *buf, uint8_t *output, size_t output_size);

/*
 * Free a buffer allocated with jb_alloc. This includes zeroing the contents
 * of the buffer in case any sensitive material was stored.
 */
void jb_free(j_buffer *buf);
