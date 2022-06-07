package org.mozilla.jss.nss;

import java.nio.ByteBuffer;

public class JByteBuffer {
    /**
     * Create a new j_buffer object with the specified number of bytes.
     *
     * See also: jbb_alloc in org/mozilla/jss/ssl/javax/j_bytebuffer.h
     */
    public static native ByteBufferProxy Create(boolean writable);

    /**
     * Removes the existing ByteBuffer from this proxy instance.
     *
     * See also: jbb_clear_buffer in org/mozilla/jss/ssl/javax/j_bytebuffer.h
     */
    public static int ClearBuffer(ByteBufferProxy proxy) {
        if (proxy == null || proxy.last == null) {
            return 0;
        }

        int offset = ClearBufferNative(proxy, proxy.last.array());
        proxy.last.position(proxy.last.position() + offset);

        proxy.last = null;

        return offset;
    }

    /**
     * Set the underlying buffer for this ByteBufferProxy instance.
     *
     * See also: jbb_set_buffer in org/mozilla/jss/ssl/javax/j_bytebuffer.h
     */
    public static void SetBuffer(ByteBufferProxy proxy, ByteBuffer buffer) {
        if (proxy == null) {
            return;
        }

        if (buffer != null && !buffer.hasArray()) {
            String msg = "Unable to support ByteBuffers which are not backed ";
            msg += "by real arrays.";
            throw new RuntimeException(msg);
        }

        if (proxy.last != null) {
            // This is an unusual case. We should always clear the last buffer
            // prior to attempting to set a new one. Luckily, we store the
            // last buffer, so we can clean up safely.
            ClearBuffer(proxy);
        }

        if (!SetBufferNative(proxy, buffer.array(), buffer.position(), buffer.limit())) {
            throw new RuntimeException("Unable to set bufer for an unknown reason.");
        }

        proxy.last = buffer;
    }

    /**
     * Get the remaining capacity of this buffer.
     *
     * See also: jbb_capacity in org/mozilla/jss/ssl/javax/j_bytebuffer.h
     */
    public static native int Capacity(ByteBufferProxy proxy);

    /**
     * Clear the underlying buffer for this ByteBufferProxy instance.
     */
    private static native int ClearBufferNative(ByteBufferProxy proxy, byte[] last);

    /**
     * Internal helper to implement the native portion of SetBuffer.
     *
     * See also: jbb_set_buffer in org/mozilla/jss/ssl/javax/j_bytebuffer.h
     */
    private static native boolean SetBufferNative(ByteBufferProxy proxy, byte[] array, long offset, long limit);

    /**
     * Destroy a buffer object, freeing its resources.
     *
     * See also: jbb_free in org/mozilla/jss/ssl/javax/j_buffer.h
     */
    public static void Free(ByteBufferProxy proxy) {
        // Make sure we call ClearBuffer ourselves; otherwise, any changes to
        // the underlying ByteBuffer won't be reflected as FreeNative will
        // discard them.
        ClearBuffer(proxy);
        FreeNative(proxy);
    }

    /**
     * Internal helper to implement the free call.
     */
    private static native void FreeNative(ByteBufferProxy proxy);
}
