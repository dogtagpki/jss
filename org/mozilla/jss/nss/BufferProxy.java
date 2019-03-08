package org.mozilla.jss.nss;

public class BufferProxy extends org.mozilla.jss.util.NativeProxy {
    public BufferProxy(byte[] pointer) {
        super(pointer);
    }

    protected native void releaseNativeResources();

    protected void finalize() throws Throwable {
        super.finalize();
    }
}
