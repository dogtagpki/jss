package org.mozilla.jss.nss;

public class Buffer {
    /**
     * Create a new j_buffer object with the specified number of bytes.
     *
     * See also: jb_alloc in org/mozilla/jss/ssl/javax/j_buffer.h
     */
    public static native BufferProxy Create(long length);

    /**
     * Check the total capacity of a buffer object.
     *
     * See also: jb_capacity in org/mozilla/jss/ssl/javax/j_buffer.h
     */
    public static native long Capacity(BufferProxy buf);

    /**
     * Check whether or not the buffer can be read from (i.e., is non-empty).
     *
     * See also: jb_can_read in org/mozilla/jss/ssl/javax/j_buffer.h
     */
    public static native boolean CanRead(BufferProxy buf);

    /**
     * Check the remaining number of bytes that can be read from the
     * buffer.
     *
     * See also: jb_read_capacity in org/mozilla/jss/ssl/javax/j_buffer.h
     */
    public static native long ReadCapacity(BufferProxy buf);

    /**
     * Check whether or not the buffer can be written to (i.e., is not full).
     *
     * See also: jb_can_write in org/mozilla/jss/ssl/javax/j_buffer.h
     */
    public static native boolean CanWrite(BufferProxy buf);

    /**
     * Check the remaining number of bytes that can be written to the
     * buffer.
     *
     * See also: jb_write_capacity in org/mozilla/jss/ssl/javax/j_buffer.h
     */
    public static native long WriteCapacity(BufferProxy buf);

    /**
     * Read the specified number of bytes from the buffer.
     *
     * See also: jb_read in org/mozilla/jss/ssl/javax/j_buffer.h
     */
    public static native byte[] Read(BufferProxy buf, long length);

    /**
     * Write the specified bytes to the buffer.
     *
     * See also: jb_write in org/mozilla/jss/ssl/javax/j_buffer.h
     */
    public static native long Write(BufferProxy buf, byte[] input);

    /**
     * Get a single character from the buffer.
     *
     * See also: jb_get in org/mozilla/jss/ssl/javax/j_buffer.h
     */
    public static native int Get(BufferProxy buf);

    /**
     * Put a single character into the buffer.
     *
     * See also: jb_put in org/mozilla/jss/ssl/javax/j_buffer.h
     */
    public static native int Put(BufferProxy buf, byte input);

    /**
     * Destroy a buffer object, freeing its resources.
     *
     * See also: jb_free in org/mozilla/jss/ssl/javax/j_buffer.h
     */
    public static native void Free(BufferProxy buf);
}
