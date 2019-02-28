package org.mozilla.jss.nss;

public class PRFDProxy extends org.mozilla.jss.util.NativeProxy {
    public PRFDProxy(byte[] pointer) {
        super(pointer);
    }

    protected native void releaseNativeResources();

    protected void finalize() throws Throwable {
        super.finalize();
    }
}
