package org.mozilla.jss.nss;

/**
 * This class provides static access to raw NSS calls with the SSL prefix,
 * and handles the usage of NativeProxy objects.
 */

import org.mozilla.jss.pkcs11.PK11Cert;
import org.mozilla.jss.pkcs11.PK11PrivKey;

import org.mozilla.jss.ssl.SSLVersionRange;

public class SSL {
    /**
     * Request certificate from the remote peer. Value for use with OptionGet
     * and OptionSet.
     *
     * See also: SSL_REQUEST_CERTIFICATE in /usr/include/nss3/ssl.h
     */
    public static final int REQUEST_CERTIFICATE = getSSLRequestCertificate();

    /**
     * Require certificate from the remote peer. Value for use with OptionGet
     * and OptionSet.
     *
     * See also: SSL_REQUIRE_CERTIFICATE in /usr/include/nss3/ssl.h
     */
    public static final int REQUIRE_CERTIFICATE = getSSLRequireCertificate();

    /**
     * Return value on success from NSS functions.
     *
     * See also: SECSuccess in /usr/include/nss3/seccomon.h
     */
    public static final int SECSuccess = getSSLSECSuccess();

    /**
     * Return value on failure from NSS functions.
     *
     * See also: SECFailure in /usr/include/nss3/seccomon.h
     */
    public static final int SECFailure = getSSLSECFailure();

    /**
     * Return value from NSS functions when the operation would block.
     *
     * See also: SECWouldBlock in /usr/include/nss3/seccomon.h
     */
    public static final int SECWouldBlock = getSSLSECWouldBlock();

    /**
     * Import a file descriptor to create a new SSL file descriptor out of it.
     *
     * See also: SSL_ImportFD in /usr/include/nss3/ssl.h
     */
    public static native PRFDProxy ImportFD(PRFDProxy model, PRFDProxy fd);

    /**
     * Set the value of a SSL option on the specified PRFileDesc.
     *
     * See also: SSL_OptionSet in /usr/include/nss3/ssl.h
     */
    public static native int OptionSet(PRFDProxy fd, int option, int val);

    /**
     * Get the value of a SSL option on the specified PRFileDesc. Note that
     * this raises an exception in the case of an invalid option.
     *
     * See also: SSL_OptionGet in /usr/include/nss3/ssl.h
     */
    public static native int OptionGet(PRFDProxy fd, int option) throws Exception;

    /**
     * Set the hostname of a handshake on the specified PRFileDesc.
     *
     * See also: SSL_SetURL in /usr/include/nss3/ssl.h
     */
    public static native int SetURL(PRFDProxy fd, String url);

    /**
     * Set the preference for a specific cipher suite on the specified
     * PRFileDesc.
     *
     * See also: SSL_CipherPrefSet in /usr/include/nss3/ssl.h
     */
    public static native int CipherPrefSet(PRFDProxy fd, int cipher, boolean enabled);

    /**
     * Get the preference for a specific cipher suite on the specified
     * PRFileDesc. Note that this can raise an Exception when the cipher
     * is unknown.
     *
     * See also: SSL_CipherPrefGet in /usr/include/nss3/ssl.h
     */
    public static native boolean CipherPrefGet(PRFDProxy fd, int cipher) throws Exception;

    /**
     * Set the range of TLS versions enabled by this server by SSLVersionRange.
     *
     * See also: SSL_VersionRangeSet in /usr/include/nss3/ssl.h
     */
    public static int VersionRangeSet(PRFDProxy fd, SSLVersionRange range) {
        return VersionRangeSetNative(fd, range.getMinEnum(), range.getMaxEnum());
    }

    /**
     * Set the range of TLS versions enabled by this server. The integer
     * parameters are values of the SSLVersion enum.
     *
     * See also: SSL_VersionRangeSet in /usr/include/nss3/ssl.h
     */
    private static native int VersionRangeSetNative(PRFDProxy fd, int min_ssl, int max_ssl);

    /**
     * Get the range of TLS versions enabled by this server.
     *
     * See also: SSL_VersionRangeSet in /usr/include/nss3/ssl.h
     */
    public static native SSLVersionRange VersionRangeGet(PRFDProxy fd) throws Exception;

    /**
     * Check the security status of a SSL handshake.
     *
     * See also: SSL_SecurityStatus in /usr/include/nss3/ssl.h
     */
    public static native SecurityStatusResult SecurityStatus(PRFDProxy fd);

    /**
     * Reset the handshake status, optionally handshaking as a server.
     *
     * See also: SSL_ResetHandshake in /usr/include/nss3/ssl.h
     */
    public static native int ResetHandshake(PRFDProxy fd, boolean asServer);

    /**
     * Force a handshake to occur if not started, else step one.
     *
     * See also: SSL_ForceHandshake in /usr/include/nss3/ssl.h
     */
    public static native int ForceHandshake(PRFDProxy fd);

    /**
     * Configure the certificate and private key for a server socket.
     *
     * @deprecated replaced with ConfigServerCert
     * See also: SSL_ConfigSecureServer in /usr/include/nss3/ssl.h
     */
    @Deprecated
    public static native int ConfigSecureServer(PRFDProxy fd, PK11Cert cert,
        PK11PrivKey key, int kea);

    /**
     * Configure the certificate and private key for a server socket. This
     * form assumes no additional data is passed.
     *
     * See also: SSL_ConfigServerCert in /usr/include/nss3/ssl.h
     */
    public static native int ConfigServerCert(PRFDProxy fd, PK11Cert cert,
        PK11PrivKey key);

    /**
     * Configure the server's session cache.
     *
     * See also: SSL_ConfigServerSessionIDCache in /usr/include/nss3/ssl.h
     */
    public static native int ConfigServerSessionIDCache(int maxCacheEntries,
        long timeout, long ssl3_timeout, String directory);

    /**
     * Introspect the peer's certificate.
     *
     * See also: SSL_PeerCertificate in /usr/include/nss3/ssl.h
     */
    public static native PK11Cert PeerCertificate(PRFDProxy fd);

    /**
     * Introspect the peer's certificate chain.
     *
     * See also: SSL_PeerCertificateChain in /usr/include/nss3/ssl.h
     */
    public static native PK11Cert[] PeerCertificateChain(PRFDProxy fd) throws Exception;

    /* Internal methods for querying constants. */
    private static native int getSSLRequestCertificate();
    private static native int getSSLRequireCertificate();
    private static native int getSSLSECSuccess();
    private static native int getSSLSECFailure();
    private static native int getSSLSECWouldBlock();
}
