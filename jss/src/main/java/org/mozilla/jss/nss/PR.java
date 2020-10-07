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
     * Return value on success from NSPR functions.
     *
     * See also: PR_SUCCESS in /usr/include/nspr4/prtypes.h
     */
    public static final int SUCCESS = getPRSuccess();

    /**
     * Return value on failure from NSPR functions.
     *
     * See also: PR_FAILURE in /usr/include/nspr4/prtypes.h
     */
    public static final int FAILURE = getPRFailure();

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
     * Close an existing PRFDProxy, clearing the pointer if successful.
     *
     * See also: PR_Close in /usr/include/nspr4/prio.h
     */
    public static int Close(PRFDProxy fd) {
        if (fd == null || fd.isNull()) {
            return SUCCESS;
        }

        return Close(fd, true);
    }

    /**
     * Close an existing PRFDProxy with an option to clear the pointer.
     *
     * See also: PR_Close in /usr/include/nspr4/prio.h
     */
    public static native int Close(PRFDProxy fd, boolean clear);

    /**
     * Close an existing SSLFDProxy.
     *
     * See also: org.mozilla.jss.nss.PR.Close
     *           org.mozilla.jss.nss.SSLFDProxy.releaseNativeResources
     */
    public synchronized static int Close(SSLFDProxy fd) throws Exception {
        if (fd == null || fd.isNull()) {
            return SUCCESS;
        }

        // Because a SSLFDProxy instance needs to free other native resources,
        // we can't release the pointer here. Instead, let NativeProxy.close()
        // handle clearing the PRFileDesc pointer.
        return Close((PRFDProxy) fd, false);
    }

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
    public static String GetErrorText() {
        byte[] text = GetErrorTextNative();
        if (text == null) {
            return "";
        }

        return new String(text);
    }
    private static native byte[] GetErrorTextNative();

    /**
     * Get the constant name of the current PR error. This is cleared on each
     * NSPR call.
     *
     * See also: PR_ErrorToName in /usr/include/nspr4/prio.h
     */
    public static String ErrorToName(int code) {
        byte[] name = ErrorToNameNative(code);
        if (name == null) {
            return "";
        }

        return new String(name);
    }
    private static native byte[] ErrorToNameNative(int code);

    /* Internal methods for querying constants. */
    private static native int getPRShutdownRcv();
    private static native int getPRShutdownSend();
    private static native int getPRShutdownBoth();
    private static native int getPRSuccess();
    private static native int getPRFailure();
}
