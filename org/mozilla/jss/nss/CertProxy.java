package org.mozilla.jss.nss;

public class CertProxy extends org.mozilla.jss.util.NativeProxy {
    public CertProxy(byte[] pointer) {
        super(pointer);
    }

    protected native void releaseNativeResources();

    protected void finalize() throws Throwable {
        super.finalize();
    }
}
