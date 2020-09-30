package org.mozilla.jss.nss;

public class PRFDProxy extends org.mozilla.jss.util.NativeProxy {
    public PRFDProxy(byte[] pointer) {
        super(pointer);
    }

    protected void releaseNativeResources() throws Exception {
        PR.Close(this);
    }

    protected void finalize() throws Throwable {
        super.finalize();
    }
}
