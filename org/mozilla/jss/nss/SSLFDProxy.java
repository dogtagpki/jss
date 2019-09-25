package org.mozilla.jss.nss;

public class SSLFDProxy extends PRFDProxy {
    public SSLFDProxy(byte[] pointer) {
        super(pointer);
    }

    protected native void releaseNativeResources();

    protected void finalize() throws Throwable {
        super.finalize();
    }
}
