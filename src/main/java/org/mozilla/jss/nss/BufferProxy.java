package org.mozilla.jss.nss;

public class BufferProxy extends org.mozilla.jss.util.NativeProxy {
    public BufferProxy(byte[] pointer) {
        super(pointer);
    }

    /**
     * It is usually better to call org.mozilla.jss.nss.Buffer.Free(...)
     * instead.
     *
     * But this does it for you.
     */
    @Override
    protected void releaseNativeResources() {
        Buffer.Free(this);
    }

    @Override
    protected void finalize() throws Throwable {
        super.finalize();
    }
}
