#include "j_bytebuffer.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <jni.h>
#include "jssutil.h"

j_bytebuffer *jbb_alloc(bool writable) {
    j_bytebuffer *buf = calloc(1, sizeof(j_bytebuffer));

    // Our j_bytebuffer doesn't initially point to any buffers; this means
    // that we're unable to read or write from this buffer.

    buf->write_allowed = writable;

    return buf;
}

size_t
jbb_clear_buffer(j_bytebuffer *buf, JNIEnv *env, jbyteArray backingArray)
{
    if (buf == NULL || env == NULL || buf->contents == NULL) {
        return 0;
    }

    // Before going to far, save the number of bytes we read/wrote in this
    // round.
    size_t ret = buf->position - buf->offset;

    if (!buf->write_allowed) {
        // We have no need to preserve the data in this buffer because we're
        // not allowed to write into it. Free our copy of the buffer data
        // and return.
        goto done;
    }

    if (backingArray == NULL) {
        return 0;
    }

    // We wish to preserve changes to our underlying byteArray, so specify 0
    // as the mode parameter.
    jbyte *data = NULL;
    jsize length = 0;
    if (!JSS_RefByteArray(env, backingArray, &data, &length)) {
        return 0;
    }

    memcpy(data, buf->contents, length);
    JSS_DerefByteArray(env, backingArray, data, 0);

done:
    free(buf->contents);
    buf->contents = NULL;
    buf->position = 0;
    buf->limit = 0;
    buf->offset = 0;

    return ret;
}

bool
jbb_set_buffer(j_bytebuffer *buf, JNIEnv *env, jbyteArray backingArray,
               size_t offset, size_t limit)
{
    if (buf == NULL || env == NULL || backingArray == NULL) {
        return false;
    }

    // Take a copy of the underlying data in the byte array, checking the
    // offset to ensure it is valid. We take a copy (rather than a reference)
    // here because the reference won't be valid once we exit from this
    // method. We need our access to the underlying data to persist out of
    // this method (and its JNI invocation), into another JNI call (likely
    // going into NSS and NSPR), and back into jbb_clear_buffer().
    size_t capacity;
    if (!JSS_FromByteArray(env, backingArray, &buf->contents, &capacity)
        || offset > capacity) {
        // We've failed to set the new data. This means RefByteArray
        // should've thrown an exception. Reset our contents to NULL
        // so we don't try using anything.
        buf->contents = NULL;
        buf->limit = 0;
        buf->position = 0;
        buf->offset = 0;
        return false;
    }

    // Otherwise, update our remaining fields with their new values.
    buf->contents = buf->contents;
    buf->limit = limit;
    buf->position = offset;
    buf->offset = offset;
    return true;
}

size_t jbb_position(j_bytebuffer *buf) {
    if (buf == NULL) {
        return 0;
    }

    return buf->position;
}

size_t jbb_capacity(j_bytebuffer *buf) {
    if (buf == NULL) {
        return 0;
    }

    return buf->limit - buf->position;
}

int jbb_put(j_bytebuffer *buf, uint8_t byte) {
    /* ret == EOF <=> can't write to the buffer */
    if (buf == NULL || buf->contents == NULL ||
        buf->position == buf->limit)
    {
        return EOF;
    }

    buf->contents[buf->position] = byte;
    buf->position += 1;

    // Semantics of put.
    return byte;
}

size_t jbb_write(j_bytebuffer *buf, const uint8_t *input, size_t input_size) {
    /* ret == 0 <=> can't write to the buffer or input_size == 0 */
    if (buf == NULL || buf->contents == NULL || input == NULL ||
        input_size == 0 || buf->position >= buf->limit || !buf->write_allowed)
    {
        return 0;
    }

    // When the input size exceeds that of the remaining space in the
    // destination buffer, update the write size to reflect the smaller
    // of the two values.
    size_t write_size = input_size;
    size_t remaining_space = buf->limit - buf->position;
    if (write_size > remaining_space) {
        write_size = remaining_space;
    }

    // Copy the data we're writing to this buffer at the specified location,
    // bounding by the reduced write size.
    memcpy(
        buf->contents + buf->position,
        input,
        write_size
    );

    // Update our position so we don't overwrite what we just wrote.
    buf->position += write_size;

    // Semantics of write.
    return write_size;
}

int jbb_get(j_bytebuffer *buf) {
    /* ret == EOF <=> can't read from the buffer */
    if (buf == NULL || buf->contents == NULL ||
        buf->position == buf->limit)
    {
        return EOF;
    }

    uint8_t result = buf->contents[buf->position];
    buf->position += 1;

    // Semantics of get.
    return result;
}

size_t jbb_read(j_bytebuffer *buf, uint8_t *output, size_t output_size) {
    /* ret == 0 <=> can't read from the buffer or output_size == 0 */
    if (buf == NULL || buf->contents == NULL || output == NULL ||
        output_size == 0 || buf->position >= buf->limit || buf->write_allowed)
    {
        return 0;
    }

    // When the output size exceeds that of the remaining space in the
    // destination buffer, update the read size to reflect the smaller of
    // the two values.
    size_t read_size = output_size;
    size_t remaining_space = buf->limit - buf->position;
    if (read_size > remaining_space) {
        read_size = remaining_space;
    }

    // Copy the data we're reading from this buffer at the specified location
    // into the output buffer, bounding by the reduced size.
    memcpy(
        output,
        buf->contents + buf->position,
        read_size
    );

    // Update our position so we don't re-read what we just read.
    buf->position += read_size;

    // Semantics of read.
    return read_size;
}

void jbb_free(j_bytebuffer *buf, JNIEnv *env) {
    // Safely handle partial or invalid structures.
    if (buf == NULL) {
        return;
    }

    // Hand the data back to its own. Usually this should be a no-op as the
    // SSLEngine should make sure to remove the byteBuffers between calls to
    // wrap/unwrap. However, in order to actually free the data, we need to
    // set buf->write_allowed = false first.
    buf->write_allowed = false;
    jbb_clear_buffer(buf, env, NULL);

    // Overwrite our data so we don't keep references to it.
    buf->contents = NULL;
    buf->limit = 0;
    buf->position = 0;
    buf->offset = 0;

    free(buf);
}
