package org.mozilla.jss.nss;

/**
 * This class provides access to useful NSPR errors, getting their values from
 * a JNI call. Note that it *isn't* an enum as the NSPR wrappers return int.
 * This saves us from having to wrap every NSPR error.
 */

public class PRErrors {
    /**
     * The call would block.
     *
     * See also: PR_WOULD_BLOCK_ERROR in /usr/include/nspr4/prerr.h
     */
    public static final int WOULD_BLOCK_ERROR = getWouldBlockError();

    private static native int getWouldBlockError();
}
