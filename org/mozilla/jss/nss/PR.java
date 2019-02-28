package org.mozilla.jss.nss;

/**
 * This class provides static access to raw NSPS calls with the PR prefix,
 * and handles the usage of NativeProxy objects.
 */

public class PR {

    public static native PRFDProxy Open(String name, int flags, int mode);

    public static native PRFDProxy NewTCPSocket();

    public static native int Close(PRFDProxy fd);

    public static native void Shutdown(PRFDProxy fd, int how);

    public static native byte[] Read(PRFDProxy fd, int amount);

    public static native byte[] Recv(PRFDProxy fd, int amount, int flags,
                                     long timeout);

    public static native int Write(PRFDProxy fd, byte[] buf);

    public static native int Send(PRFDProxy fd, byte[] buf, int flags,
                                  long timeout);
}
