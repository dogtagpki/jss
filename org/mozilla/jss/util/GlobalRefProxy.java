package org.mozilla.jss.util;

public class GlobalRefProxy extends NativeProxy {
    public GlobalRefProxy(byte[] pointer) {
        super(pointer);
    }

    protected native void releaseNativeResources();
}
