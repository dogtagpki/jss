#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include <jni.h>

#pragma once

/*
 * Opaque structure for using byte buffers from C/JNI. Subject to change at
 * any time.
 *
 * A j_bytebuffer is an interface over a ByteBuffer, for backing IO in
 * JSSEngineOptimizedImpl. It is only meant to either write or read from
 * the given buffer; doing both from a single buffer is likely to fail.
 *
 * In particular, this structure is useful for invoking a NSPR read/write call
 * on a pair of ByteBuffers where one is the data to read from (as if it came
 * off the wire) and the other is the data to write to (as if it were going
 * to the wire). Before each transaction, this structure is updated with the
 * current set of buffers. The NSPR call is then performed and the buffers
 * should be immediately cleared so no future NSPR call uses them.
 */
typedef struct {
    /* Contents of the buffer. Populated via a call to .array() and offset by
     * .position(). */
    uint8_t *contents;

    /* Limit is used as a sentinel value; when position == limit,
     * can't write or read from this buffer. */
    size_t limit;

    /* Next position to write or read from. */
    size_t position;

    /* Original position we started at. */
    size_t offset;

    /* Defines whether or not we're reading or writing to this buffer; if
     * false, we're not allowed to write and jbb_release_buffer won't attempt
     * to copy any data back. */
    bool write_allowed;
} j_bytebuffer;

/*
 * Create a new buffer; must be freed with jbb_free.
 */
j_bytebuffer *jbb_alloc(bool writable);

/*
 * Remove the buffers from this j_bytebuffer structure.
 */
size_t jbb_clear_buffer(j_bytebuffer *buf, JNIEnv *env,
                        jbyteArray backingArray);

/*
 * Update this j_bytebuffer struct with the information from a ByteBuffer.
 */
bool jbb_set_buffer(j_bytebuffer *buf, JNIEnv *env, jbyteArray backingArray,
                    size_t offset, size_t limit);

/* Get the current position of the specified buffer; used for updating the
 * original ByteBuffer. */
size_t jbb_position(j_bytebuffer *buf);

/* Get the remaining capacity in this byte buffer. */
size_t jbb_capacity(j_bytebuffer *buf);

/*
 * Store a character into the buffer. Returns the character if stored,
 * else EOF if unable to store the character (because the buffer is full).
 * When not EOF, can safely be casted to a uint8_t.
 */
int jbb_put(j_bytebuffer *buf, uint8_t byte);

/*
 * Store many characters into the buffer from an array of characters. Returns
 * the number of characters written into the buffer; max of input_size. This
 * is zero when the buffer is already full.
 */
size_t jbb_write(j_bytebuffer *buf, const uint8_t *input, size_t input_size);

/*
 * Get the next character from the buffer or EOF if the buffer is empty. If
 * not EOF, can safely be casted to uint8_t.
 */
int jbb_get(j_bytebuffer *buf);

/*
 * Read several characters from the buffer in the order they were written. The
 * characters are placed in output and up to output_size characters are read.
 * Returns the number of characters read; zero if the buffer was empty.
 */
size_t jbb_read(j_bytebuffer *buf, uint8_t *output, size_t output_size);

/*
 * Free a buffer allocated with jbb_alloc. Note that if jbb_set_buffer isn't
 * called prior to this, we'll copy and release the underlying buffers back
 * to the backing jbyteArray here. Pass NULL for the env parameter to skip
 * this.
 */
void jbb_free(j_bytebuffer *buf, JNIEnv *env);
