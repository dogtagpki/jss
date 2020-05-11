package org.mozilla.jss.nss;

import java.nio.ByteBuffer;

public class ByteBufferProxy extends org.mozilla.jss.util.NativeProxy {
    protected ByteBuffer last;

    public ByteBufferProxy(byte[] pointer) {
        super(pointer);
    }

    /**
     * It is usually better to call org.mozilla.jss.nss.JByteBuffer.Free(...)
     * instead.
     *
     * But this does it for you.
     */
    protected void releaseNativeResources() {
        JByteBuffer.Free(this);
    }

    protected void finalize() throws Throwable {
        super.finalize();
    }
}
