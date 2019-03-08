package org.mozilla.jss.nss;

public class Buffer {
    public static native BufferProxy Create(long length);

    public static native long Capacity(BufferProxy buf);
    public static native boolean CanRead(BufferProxy buf);
    public static native boolean CanWrite(BufferProxy buf);

    public static native byte[] Read(BufferProxy buf, long length);
    public static native long Write(BufferProxy buf, byte[] input);

    public static native int Get(BufferProxy buf);
    public static native int Put(BufferProxy buf, byte input);

    public static native void Free(BufferProxy buf);
}
