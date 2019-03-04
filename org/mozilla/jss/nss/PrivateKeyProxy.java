package org.mozilla.jss.nss;

public class PrivateKeyProxy extends org.mozilla.jss.util.NativeProxy {
    public PrivateKeyProxy(byte[] pointer) {
        super(pointer);
    }

    protected native void releaseNativeResources();

    protected void finalize() throws Throwable {
        super.finalize();
    }
}
