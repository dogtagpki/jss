package org.mozilla.jss.nss;

/**
 * This class provides static access to raw NSPS calls with the PR prefix,
 * and handles the usage of NativeProxy objects.
 */

public class PR {
    /**
     * Shut down the receiving side of the TCP connection.
     *
     * See also: Shutdown
    */
    public static final int SHUTDOWN_RCV = getPRShutdownRcv();

    /**
     * Shut down the sending side of the TCP connection.
     *
     * See also: Shutdown
     */
    public static final int SHUTDOWN_SEND = getPRShutdownSend();

    /**
     * Shut down both sides of the TCP connection.
     *
     * See also: Shutdown
     */
    public static final int SHUTDOWN_BOTH = getPRShutdownBoth();

    /**
     * Open the file at name (with the specified flags and mode) and create
     * a new PRFDProxy (to a NSPR PRFileDesc *) for that file.
     *
     * See also: PR_Open in /usr/include/nspr4/prio.h
     */
    public static native PRFDProxy Open(String name, int flags, int mode);

    /**
     * Open a new TCP Socket and create a new PRFDProxy for that socket.
     *
     * See also: PR_NewTCPSocket in /usr/include/nspr4/prio.h
     */
    public static native PRFDProxy NewTCPSocket();

    /**
     * Create a new j_buffer backed PRFileDesc, mimicing a TCP socket with
     * the specified peer_info.
     *
     * See also: newBufferPRFileDesc in org/mozilla/jss/ssl/javax/BufferPRFD.h
     */
    public static native PRFDProxy NewBufferPRFD(BufferProxy read_buf,
                                                 BufferProxy write_buf,
                                                 byte[] peer_info);
    /**
     * Close an existing PRFDProxy.
     *
     * See also: PR_Close in /usr/include/nspr4/prio.h
     */
    public static native int Close(PRFDProxy fd);

    /**
     * Shutdown an existing PRFDProxy.
     * This is usually used with TCP modes.
     *
     * See also: PR_Shutdown in /usr/include/nspr4/prio.h
     */
    public static native int Shutdown(PRFDProxy fd, int how);

    /**
     * Read up to amount bytes from a PRFDProxy.
     *
     * See also: PR_Read in /usr/include/nspr4/prio.h
     */
    public static native byte[] Read(PRFDProxy fd, int amount);

    /**
     * Recv up to amount bytes from a PRFDProxy, given the specified receive
     * flags and timeout value.
     *
     * See also: PR_Recv in /usr/include/nspr4/prio.h
     */
    public static native byte[] Recv(PRFDProxy fd, int amount, int flags,
                                     long timeout);

    /**
     * Write the specified bytes to the PRFDProxy.
     *
     * Note: Unlike PR_Write, this method assumes the entire buffer is being
     * written.
     *
     * See also: PR_Write in /usr/include/nspr4/prio.h
     */
    public static native int Write(PRFDProxy fd, byte[] buf);

    /**
     * Send the specified bytes via the PRFDProxy, given the specified
     * send flags and timeout value.
     *
     * See also: PR_Send in /usr/include/nspr4/prio.h
     */
    public static native int Send(PRFDProxy fd, byte[] buf, int flags,
                                  long timeout);

    /**
     * Get the value of the current PR error. This is cleared on each NSPR
     * call.
     *
     * See also: PR_GetError in /usr/include/nspr4/prio.h
     */
    public static native int GetError();

    /**
     * Get the error text of the current PR error. This is cleared on each
     * NSPR call.
     *
     * See also: PR_GetErrorText in /usr/include/nspr4/prio.h
     */
    public static native byte[] GetErrorText();

    /* Internal methods for querying constants. */
    private static native int getPRShutdownRcv();
    private static native int getPRShutdownSend();
    private static native int getPRShutdownBoth();
}
