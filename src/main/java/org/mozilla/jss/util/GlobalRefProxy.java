package org.mozilla.jss.util;

public class GlobalRefProxy extends NativeProxy {
    public GlobalRefProxy(byte[] pointer) {
        super(pointer);
    }

    public GlobalRefProxy(Object target) {
        super(GlobalRefProxy.refOf(target));
    }

    private static native byte[] refOf(Object target);

    @Override
    protected synchronized void releaseNativeResources() {
        clear();
    }
}
