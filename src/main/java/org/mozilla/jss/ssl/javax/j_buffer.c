#include "j_buffer.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

j_buffer *jb_alloc(size_t length) {
    j_buffer *buf = calloc(1, sizeof(j_buffer));
    buf->contents = calloc(length, sizeof(uint8_t));

    buf->capacity = length;

    // In the beginning, we can only write, not read. Hence, set our read_pos
    // to the sentinel value, buf->capacity.
    buf->write_pos = 0;
    buf->read_pos = length;

    return buf;
}

size_t jb_capacity(j_buffer *buf) {
    if (buf == NULL) {
        return 0;
    }

    return buf->capacity;
}

bool jb_can_read(j_buffer *buf) {
    /* buf->read_pos == buf->capacity <=> can't read from the buffer */
    return buf != NULL && buf->read_pos != buf->capacity;
}

size_t jb_read_capacity(j_buffer *buf) {
    if (buf == NULL) {
        return 0;
    }

    /* Semantics: buf->read_pos == buf->capacity <=> can't read */
    if (buf->read_pos == buf->capacity) {
        return 0;
    }

    /* Semantics: buf->write_pos == buf->capacity <=> buffer empty */
    if (buf->write_pos == buf->capacity) {
        return buf->capacity;
    }

    /* When buf->read_pos < buf->write_pos, delta is what we can read */
    if (buf->read_pos < buf->write_pos) {
        return buf->write_pos - buf->read_pos;
    }

    /* Lastly, we can read to the end of the buffer and back around to
     * write_pos when buf->read_pos > buf->write_pos. Note that it is
     * never true that buf->read_pos == buf->write_pos. */
    return (buf->capacity - buf->read_pos) + buf->write_pos;
}

bool jb_can_write(j_buffer *buf) {
    /* buf->write_pos == buf->capacity <=> can't write to the buffer */
    return buf != NULL && buf->write_pos != buf->capacity;
}

size_t jb_write_capacity(j_buffer *buf) {
    if (buf == NULL) {
        return 0;
    }

    /* Semantics: buf->write_pos == buf->capacity <=> can't write */
    if (buf->write_pos == buf->capacity) {
        return 0;
    }

    /* Semantics: buf->read_pos == buf->capacity <=> can't read */
    if (buf->read_pos == buf->capacity) {
        return buf->capacity;
    }

    /* When buf->write_pos < buf->read_pos, delta is what we can write */
    if (buf->write_pos < buf->read_pos) {
        return buf->read_pos - buf->write_pos;
    }

    /* Lastly, we can write to the end of the buffer and back around to
     * write_pos when buf->write_pos > buf->read_pos */
    return (buf->capacity - buf->write_pos) + buf->read_pos;
}

int jb_put(j_buffer *buf, uint8_t byte) {
    /* ret == EOF <=> can't write to the buffer */
    /* ret = char written <=> can write to the buffer */
    if (!jb_can_write(buf)) {
        return EOF;
    }

    buf->contents[buf->write_pos] = byte;

    if (buf->read_pos == buf->capacity) {
        // As we just performed a write, we can now read, starting at this
        // location.
        buf->read_pos = buf->write_pos;
    }

    buf->write_pos += 1;
    if (buf->write_pos == buf->capacity && buf->read_pos > 0) {
        // If we've incremented write_pos and reached the limit of our
        // capacity, when read_pos is not at the head of the buffer, we can
        // write another character, so set the write_pos to the head.
        buf->write_pos = 0;
    }
    if (buf->write_pos == buf->read_pos) {
        // If we've incremented buf->write_pos and hit buf->read_pos, then we
        // can't write any more bytes. This is because we've already reset
        // buf->read_pos when it was at capacity, so if the condition holds,
        // either buf->write_pos != buf->capacity or buf->read_pos !=
        // buf->capacity.
        buf->write_pos = buf->capacity;
    }

    // Semantics of put.
    return byte;
}

size_t jb_write(j_buffer *buf, const uint8_t *input, size_t input_size) {
    /* ret == 0 <=> can't write to the buffer or input_size == 0 */
    /* ret == amount written <=> can write to the buffer */
    if (!jb_can_write(buf) || input_size == 0) {
        return 0;
    }

    // Quantity we should write in our first batch.
    size_t write_size = buf->capacity - buf->write_pos;

    // Location (offset from buf->contents) we should write to.
    uint8_t *write_ptr = buf->contents + buf->write_pos;

    if (buf->read_pos > buf->write_pos) {
        // When buf->read_pos > buf->write_pos, we know that we are limited
        // in the quantity we can write by buf->read_pos. (If buf->read_pos <
        // buf->write_pos, we are not limited and can read up to capacity).
        // Since we guarantee buf->read_pos <= buf->capacity, this subtraction
        // will not grow the size written and only shrink it.
        write_size = buf->read_pos - buf->write_pos;
    }
    if (write_size > input_size) {
        // Since we're limited by the amount we can ultimately write by the
        // quantity of bytes of input we have, shrink write_size since it was
        // previously greater than input_size.
        write_size = input_size;
    }

    // Note that, sometimes write_size is computed as being smaller than
    // input_size. This happens when write_pos is towards the end of the
    // buffer, but read_pos is not at the start. Thus we can write more
    // bytes than we computed above. To handle this, we call jb_write
    // again after this pass. In the above we ensure that we always write
    // at least one byte, so input_size shrinks and buf->write_pos moves.
    // This ensures we make at most two calls to jb_write and have a recursion
    // depth of at most two.

    // This copies the current byte window from the input to the buffer.
    memcpy(write_ptr, input, write_size);

    if (buf->read_pos == buf->capacity) {
        // Since we just wrote bytes, we can now read bytes again.
        buf->read_pos = buf->write_pos;
    }

    // Since write_size is bounded above by the difference between
    // buf->capacity and buf->write_pos, we guarantee that
    // buf->write_pos <= buf->capacity after adding write_size.
    buf->write_pos += write_size;

    if (buf->write_pos == buf->capacity && buf->read_pos != 0) {
        // If we're at capacity but buf->read_pos isn't the start of the
        // buffer, we can update write_pos to be the head. In this case,
        // when write_size < input_size, we can write again, hence why we
        // call jb_write at the end.
        buf->write_pos = 0;
    }
    if (buf->write_pos == buf->read_pos) {
        // In this case, we've written the most we can until we ran into
        // read_pos, so we lack space to write again, so update write_pos
        // to be the capacity of the buffer.
        buf->write_pos = buf->capacity;
    }

    // Since we can recurse, update input (the pointer to where we're
    // writing), by the write_size so that the next byte is placed correctly.
    // Also, update input_size by write_size such that the remaining capacity
    // of the input buffer (or, the offset input buffer) is reflected.
    input += write_size;
    input_size -= write_size;

    // Recurse, updating the return value by this write size.
    return write_size + jb_write(buf, input, input_size);
}

int jb_get(j_buffer *buf) {
    /* ret == EOF <=> can't read from the buffer */
    if (!jb_can_read(buf)) {
        return EOF;
    }

    uint8_t result = buf->contents[buf->read_pos];

    if (buf->write_pos == buf->capacity) {
        // Since we just read from the buffer, we now have a place to write
        // to since it wasn't possible before.
        buf->write_pos = buf->read_pos;
    }

    // Always increment read_pos since we read a byte.
    buf->read_pos += 1;
    if (buf->read_pos == buf->capacity && buf->write_pos != 0) {
        // When the read_pos is now at capacity, but write_pos is not at the
        // start of the buffer, we can wrap read_pos and read more bytes.
        buf->read_pos = 0;
    }
    if (buf->read_pos == buf->write_pos) {
        // If incrementing read_pos put it equal with write_pos, we can no
        // longer read more bytes, so set it to buf->capacity.
        buf->read_pos = buf->capacity;
    }

    // Return the byte we read.
    return result;
}

size_t jb_read(j_buffer *buf, uint8_t *output, size_t output_size) {
    /* ret == 0 <=> can't read from the buffer or output_size == 0 */
    /* ret == amount written <=> can read from the buffer */
    if (!jb_can_read(buf) || output_size == 0) {
        return 0;
    }

    // Location we should read from: buf->contents + the offset given by
    // buf->read_pos.
    uint8_t *read_ptr = buf->contents + buf->read_pos;

    // Size of the read we should perform. We're always bounded above by the
    // difference between buf->capacity and buf->read_pos.
    size_t read_size = buf->capacity - buf->read_pos;

    if (buf->write_pos > buf->read_pos) {
        // When the condition holds and since buf->write_pos <= buf->capacity,
        // update read_size to be the difference between buf->write_pos and
        // buf->read_pos. This will thus never grow read_size.
        read_size = buf->write_pos - buf->read_pos;
    }
    if (read_size > output_size) {
        // Bound read_size by output_size when read_size exceeds output_size.
        read_size = output_size;
    }

    // We perform the initial copy of bytes from buf->contents to the output
    // buffer. However, we might need another pass, hence the recursion at the
    // end of jb_read. For more discussion, see the documentation in
    memcpy(output, read_ptr, read_size);

    if (buf->write_pos == buf->capacity) {
        // Since we just read from the buffer, we can now write to the buffer
        // at the location we just read from.
        buf->write_pos = buf->read_pos;
    }

    buf->read_pos += read_size;

    if (buf->read_pos == buf->capacity && buf->write_pos != 0) {
        // When we've reached buf->capacity and buf->write_pos isn't at the
        // start, we can read more bytes, so set buf->read_pos to the start
        // of the buffer.
        buf->read_pos = 0;
    }
    if (buf->read_pos == buf->write_pos) {
        // When buf->read_pos is buf->write_pos, we can no longer read any
        // more bytes from the buffer, so set buf->read_pos to our sentinel,
        // buf->capacity.
        buf->read_pos = buf->capacity;
    }

    // Move our output array by read_size and decrease its given size to
    // handle the recursion into jb_read.
    output += read_size;
    output_size -= read_size;
    return read_size + jb_read(buf, output, output_size);
}

void jb_free(j_buffer *buf) {
    // Safely handle partial or invalid structures.
    if (buf == NULL) {
        return;
    }
    if (buf->contents == NULL || buf->capacity == 0) {
        return;
    }

    // We clear the contents of the buffer before freeing it in case any
    // sensitive information was stored.
    memset(buf->contents, 0, buf->capacity);
    free(buf->contents);

    // Safe guards to ensure we don't try and free buf again.
    buf->contents = NULL;
    buf->capacity = 0;

    free(buf);
}
