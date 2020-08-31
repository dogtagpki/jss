package org.mozilla.jss.nss;

/**
 * This class provides access to useful NSS/SSL errors, getting their values
 * from a JNI call. Note that it *isn't* an enum as the NSS wrappers return
 * int. This saves us from having to wrap every NSS error in a class instance
 * only to later unwrap it to make any useful calls.
 */

public class SSLErrors {
    /**
     * Certificate has a bad hostname.
     *
     * See also:  in /usr/include/nss3/sslcerr.h
     */
    public static final int BAD_CERT_DOMAIN = getBadCertDomain();

    private static native int getBadCertDomain();
}
