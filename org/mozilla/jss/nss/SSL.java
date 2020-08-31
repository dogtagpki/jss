package org.mozilla.jss.nss;

/**
 * This class provides static access to raw NSS calls with the SSL prefix,
 * and handles the usage of NativeProxy objects.
 */

import java.util.ArrayList;

import org.mozilla.jss.pkcs11.PK11Cert;
import org.mozilla.jss.pkcs11.PK11PrivKey;

import org.mozilla.jss.ssl.SSLAlertEvent;
import org.mozilla.jss.ssl.SSLProtocolVariant;
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
     * Enable post-handshake authentication extension. Value for use with
     * OptionGet.
     *
     * See also: SSL_ENABLE_POST_HANDSHAKE_AUTH in /usr/include/nss3/ssl.h
     */
    public static final int ENABLE_POST_HANDSHAKE_AUTH = getSSLEnablePostHandshakeAuth();

    /**
     * Option for configuring renegotiation after initial handshake. Value for
     * use with OptionGet and OptionSet.
     *
     * See also: SSL_ENABLE_RENEGOTIATION in /usr/include/nss3/ssl.h
     */
    public static final int ENABLE_RENEGOTIATION = getSSLEnableRenegotiation();

    /**
     * Option for requiring safe negotiation. Value for use with OptionGet and
     * OptionSet.
     *
     * See also: SSL_REQUIRE_SAFE_NEGOTIATION in /usr/include/nss3/ssl.h
     */
    public static final int REQUIRE_SAFE_NEGOTIATION = getSSLRequireSafeNegotiation();

    /**
     * Value for never allowing renegotiation after initial handshake. Value
     * for use with ENABLE_RENEGOTIATION with OptionGet and OptionSet.
     *
     * See also: SSL_RENEGOTIATE_NEVER in /usr/include/nss3/ssl.h
     */
    public static final int RENEGOTIATE_NEVER = getSSLRenegotiateNever();

    /**
     * Value for always allowing renegotiation after initial handshake,
     * regardless of whether or not the peer's client hellow bears the
     * renegotiation info extension; unsafe. Value for use with
     * ENABLE_RENEGOTIATION with OptionGet and OptionSet.
     *
     * See also: SSL_RENEGOTIATE_UNRESTRICTED in /usr/include/nss3/ssl.h
     */
    public static final int RENEGOTIATE_UNRESTRICTED = getSSLRenegotiateUnrestricted();

    /**
     * Value for allowing renegotiation after initial handshake with the TLS
     * renegotiation_info extension; safe. Value for use with
     * ENABLE_RENEGOTIATION with OptionGet and OptionSet.
     *
     * See also: SSL_RENEGOTIATE_REQUIRES_XTN in /usr/include/nss3/ssl.h
     */
    public static final int RENEGOTIATE_REQUIRES_XTN = getSSLRenegotiateRequiresXtn();

    /**
     * Value for disallowing unsafe renegotiation in server sockets only, but
     * allows clients to continue to renegotiate with vulnerable servers.
     * Value for use with ENABLE_RENEGOTIATION with OptionGet and OptionSet.
     *
     * See also: SSL_RENEGOTIATE_TRANSITIONAL in /usr/include/nss3/ssl.h
     */
    public static final int RENEGOTIATE_TRANSITIONAL = getSSLRenegotiateTransitional();

    /**
     * Option for sending SCSV in handshakes. Value for use with OptionGet and
     * OptionSet.
     *
     * See also: SSL_ENABLE_FALLBACK_SCSV in /usr/include/nss3/ssl.h
     */
    public static final int ENABLE_FALLBACK_SCSV = getSSLEnableFallbackSCSV();

    /**
     * Value for never requiring a certificate. Value for use with
     * SSL_REQUIRE_CERTIFICATE with OptionGet and OptionSet.
     *
     * See also: SSL_REQUIRE_NEVER in /usr/include/nss3/ssl.h
     */
    public static final int REQUIRE_NEVER = getSSLRequireNever();

    /**
     * Value for always requiring a certificate. Value for use with
     * SSL_REQUIRE_CERTIFICATE with OptionGet and OptionSet.
     *
     * See also: SSL_REQUIRE_ALWAYS in /usr/include/nss3/ssl.h
     */
    public static final int REQUIRE_ALWAYS = getSSLRequireAlways();

    /**
     * Value for requiring a certificate only on the first handshake. Value
     * for use with SSL_REQUIRE_CERTIFICATE with OptionGet and OptionSet.
     *
     * See also: SSL_REQUIRE_FIRST_HANDSHAKE in /usr/include/nss3/ssl.h
     */
    public static final int REQUIRE_FIRST_HANDSHAKE = getSSLRequireFirstHandshake();

    /**
     * Value for requiring a certificate but not erring if the peer doesn't
     * provide one. Value for use with SSL_REQUIRE_CERTIFICATE with OptionGet
     * and OptionSet.
     *
     * See also: SSL_REQUIRE_NO_ERROR in /usr/include/nss3/ssl.h
     */
    public static final int REQUIRE_NO_ERROR = getSSLRequireNoError();

    /**
     * Import a file descriptor to create a new SSL file descriptor out of it.
     *
     * See also: SSL_ImportFD in /usr/include/nss3/ssl.h
     */
    public static SSLFDProxy ImportFD(PRFDProxy model, PRFDProxy fd) {
        if (fd == null) {
            throw new NullPointerException("Expected fd != null");
        }

        byte[] ptr = ImportFDNative(model, fd);
        if (ptr == null || ptr.length == 0) {
            int error = PR.GetError();
            throw new NullPointerException("SSL_ImportFD failed: " + PR.ErrorToName(error) + " (" + error + ")");
        }

        fd.clear();

        return new SSLFDProxy(ptr);
    }

    public static native byte[] ImportFDNative(PRFDProxy model, PRFDProxy fd);

    /**
     * Set the value of a SSL option on the specified PRFileDesc.
     *
     * See also: SSL_OptionSet in /usr/include/nss3/ssl.h
     */
    public static native int OptionSet(SSLFDProxy fd, int option, int val);

    /**
     * Get the value of a SSL option on the specified PRFileDesc. Note that
     * this raises an exception in the case of an invalid option.
     *
     * See also: SSL_OptionGet in /usr/include/nss3/ssl.h
     */
    public static native int OptionGet(SSLFDProxy fd, int option) throws Exception;

    /**
     * Set the hostname of a handshake on the specified PRFileDesc.
     *
     * See also: SSL_SetURL in /usr/include/nss3/ssl.h
     */
    public static native int SetURL(SSLFDProxy fd, String url);

    /**
     * Set the preference for a specific cipher suite on the specified
     * PRFileDesc.
     *
     * See also: SSL_CipherPrefSet in /usr/include/nss3/ssl.h
     */
    public static native int CipherPrefSet(SSLFDProxy fd, int cipher, boolean enabled);

    /**
     * Get the preference for a specific cipher suite on the specified
     * PRFileDesc. Note that this can raise an Exception when the cipher
     * is unknown.
     *
     * See also: SSL_CipherPrefGet in /usr/include/nss3/ssl.h
     */
    public static native boolean CipherPrefGet(SSLFDProxy fd, int cipher) throws Exception;

    /**
     * Set the default preferences for a specific cipher suite across all
     * future PRFileDesc's.
     *
     * See also: SSL_CipherPrefSetDefault in /usr/include/nss3/ssl.h
     */
    public static native int CipherPrefSetDefault(int cipher, boolean enabled);

    /**
     * Get the default preferences for a specific cipher suite across all
     * future PRFileDesc's. Note that this can raise an Exception when the
     * cipher is unknown.
     *
     * See also: SSL_CipherPrefGetDefault in /usr/include/nss3/ssl.h
     */
    public static native boolean CipherPrefGetDefault(int cipher);

    /**
     * Set the range of TLS versions enabled by this server by SSLVersionRange.
     *
     * See also: SSL_VersionRangeSet in /usr/include/nss3/ssl.h
     */
    public static int VersionRangeSet(SSLFDProxy fd, SSLVersionRange range) {
        return VersionRangeSetNative(fd, range.getMinEnum(), range.getMaxEnum());
    }

    /**
     * Set the range of TLS versions enabled by this server. The integer
     * parameters are values of the SSLVersion enum.
     *
     * See also: SSL_VersionRangeSet in /usr/include/nss3/ssl.h
     */
    private static native int VersionRangeSetNative(SSLFDProxy fd, int min_ssl, int max_ssl);

    /**
     * Get the range of TLS versions enabled by this server.
     *
     * See also: SSL_VersionRangeSet in /usr/include/nss3/ssl.h
     */
    public static native SSLVersionRange VersionRangeGet(SSLFDProxy fd) throws Exception;

    /**
     * Set the range of TLS versions enabled by default, for all future
     * PRFileDesc's of the default protocol variant type, STREAM.
     *
     * See also: SSL_VersionRangeSetDefault in /usr/include/nss3/ssl.h
     */
    public static int VersionRangeSetDefault(SSLVersionRange range) {
        return VersionRangeSetDefault(SSLProtocolVariant.STREAM, range);
    }

    /**
     * Set the range of TLS versions enabled by default, for all future
     * PRFileDesc's of the specified protocol variant.
     *
     * See also: SSL_VersionRangeSetDefault in /usr/include/nss3/ssl.h
     */
    public static int VersionRangeSetDefault(SSLProtocolVariant variant, SSLVersionRange range) {
        return VersionRangeSetDefaultNative(variant.getEnum(), range.getMinEnum(), range.getMaxEnum());
    }

    /**
     * Set the range of default TLS versions enabled in all future
     * PRFileDesc's. The integer parameters are values of the SSLVersion enum.
     *
     * See also: SSL_VersionRangeSet in /usr/include/nss3/ssl.h
     */
    private static native int VersionRangeSetDefaultNative(int variant_ssl, int min_ssl, int max_ssl);

    /**
     * Get the range of TLS versions enabled in all future PRFileDesc's of the
     * default STREAM protocol variant..
     *
     * See also: SSL_VersionRangeGetDefault in /usr/include/nss3/ssl.h
     */
    public static SSLVersionRange VersionRangeGetDefault() {
        return VersionRangeGetDefault(SSLProtocolVariant.STREAM);
    }

    /**
     * Get the range of TLS versions enabled in all future PRFileDesc's of the
     * specified protocol variant.
     *
     * See also: SSL_VersionRangeGetDefault in /usr/include/nss3/ssl.h
     */
    public static SSLVersionRange VersionRangeGetDefault(SSLProtocolVariant variant) {
        return VersionRangeGetDefaultNative(variant.getEnum());
    }

    private static native SSLVersionRange VersionRangeGetDefaultNative(int variant);

    /**
     * Check the security status of a SSL handshake.
     *
     * See also: SSL_SecurityStatus in /usr/include/nss3/ssl.h
     */
    public static native SecurityStatusResult SecurityStatus(SSLFDProxy fd);

    /**
     * Inquire for SSL Channel Information after the handshake has completed.
     *
     * See also: SSL_GetChannelInfo in /usr/include/nss3/ssl.h
     */
    public static native SSLChannelInfo GetChannelInfo(SSLFDProxy fd);

    /**
     * Inquire for SSL Channel Information before the handshake has completed.
     *
     * See also: SSL_GetPreliminaryChannelInfo in /usr/include/nss3/ssl.h
     */
    public static native SSLPreliminaryChannelInfo GetPreliminaryChannelInfo(SSLFDProxy fd);

    /**
     * Reset the handshake status, optionally handshaking as a server.
     *
     * See also: SSL_ResetHandshake in /usr/include/nss3/ssl.h
     */
    public static native int ResetHandshake(SSLFDProxy fd, boolean asServer);

    /**
     * Rehandshake an existing socket, optionally flushing the cache line.
     *
     * See also: SSL_ReHandshake in /usr/include/nss3/ssl.h
     */
    public static native int ReHandshake(SSLFDProxy fd, boolean flushCache);

    /**
     * Force a handshake to occur if not started, else step one.
     *
     * See also: SSL_ForceHandshake in /usr/include/nss3/ssl.h
     */
    public static native int ForceHandshake(SSLFDProxy fd);

    /**
     * Configure the certificate and private key for a server socket.
     *
     * @deprecated replaced with ConfigServerCert
     * See also: SSL_ConfigSecureServer in /usr/include/nss3/ssl.h
     */
    @Deprecated
    public static native int ConfigSecureServer(SSLFDProxy fd, PK11Cert cert,
        PK11PrivKey key, int kea);

    /**
     * Configure the certificate and private key for a server socket. This
     * form assumes no additional data is passed.
     *
     * See also: SSL_ConfigServerCert in /usr/include/nss3/ssl.h
     */
    public static native int ConfigServerCert(SSLFDProxy fd, PK11Cert cert,
        PK11PrivKey key);

    /**
     * Configure the server's session cache.
     *
     * See also: SSL_ConfigServerSessionIDCache in /usr/include/nss3/ssl.h
     */
    public synchronized static native int ConfigServerSessionIDCache(int maxCacheEntries,
        long timeout, long ssl3_timeout, String directory);

    /**
     * Invalidate the SSL session associated with this socket.
     *
     * See also: SSL_InvalidateSession in /usr/include/nss3/ssl.h
     */
    public static native int InvalidateSession(SSLFDProxy fd);

    /**
     * Introspect the peer's certificate.
     *
     * See also: SSL_PeerCertificate in /usr/include/nss3/ssl.h
     */
    public static native PK11Cert PeerCertificate(SSLFDProxy fd);

    /**
     * Introspect the peer's certificate chain.
     *
     * See also: SSL_PeerCertificateChain in /usr/include/nss3/ssl.h
     */
    public static native PK11Cert[] PeerCertificateChain(SSLFDProxy fd) throws Exception;

    /**
     * Send the TLS 1.3 Certificate Request as a server; experimental.
     *
     * See also: SSL_SendCertificateRequest in /usr/include/nss3/sslexp.h
     */
    public static native int SendCertificateRequest(SSLFDProxy fd);

    /**
     * Send the TLS 1.3 KeyUpdate Request; experimental.
     *
     * See also: SSL_KeyUpdate in /usr/include/nss3/sslexp.h
     */
    public static native int KeyUpdate(SSLFDProxy fd, boolean requestUpdate);

    /**
     * Use client authentication; set client certificate from SSLFDProxy.
     *
     * See also: SSL_GetClientAuthDataHook in /usr/include/nss3/ssl.h,
     *           org.mozilla.jss.nss.SSLFDProxy.SetClientCert(...)
     */
    public static native int AttachClientCertCallback(SSLFDProxy fd);

    /**
     * Enable recording of alerts in the SSLFDProxy object.
     *
     * See also: SSL_AlertReceivedCallback in /usr/include/nss3/ssl.h,
     *           SSL_AlertSentCallback in /usr/include/nss3/ssl.h
     */
    public static int EnableAlertLogging(SSLFDProxy fd) {
        fd.inboundAlerts = new ArrayList<SSLAlertEvent>();
        fd.inboundOffset = 0;
        fd.outboundAlerts = new ArrayList<SSLAlertEvent>();
        fd.outboundOffset = 0;

        return EnableAlertLoggingNative(fd);
    }

    /* Internal helper for EnableAlertLogging method. */
    private static native int EnableAlertLoggingNative(SSLFDProxy fd);

    /**
     * Use the default JSS certificate checking handler (which understands
     * CryptoManager OCSP status).
     *
     * See also: SSL_AuthCertificateHook in /usr/include/nss3/ssl.h and
     *           JSSL_DefaultCertAuthCallback in jss/ssl/callbacks.c
     */
    public static native int ConfigJSSDefaultCertAuthCallback(SSLFDProxy fd);

    /**
     * Use an asynchronous certificate checking handler which allows us to
     * invoke an arbitrary number of TrustManagers. This makes functions like
     * SSL_ForceHandshake, PR_Read, and PR_Write return back to the caller
     * when cert auth is required. We set the SSLFDProxy.needCertValidation
     * field to true in this case. Set this field to false and call
     * SSL_AuthCertificateComplete with the status code of the error (0 if
     * the cert is valid), and resume handshaking.
     *
     * See also: SSL_AuthCertificateHook in /usr/include/nss3/ssl.h and
     *           JSSL_SSLFDAsyncCertAuthCallback in jss/nss/SSLFDProxy.c
     */
    public static native int ConfigAsyncTrustManagerCertAuthCallback(SSLFDProxy fd);

    /**
     * Use a synchronous certificate checking handler based off the SSLFDProxy
     * proper. This allows us to invoke an arbitrary number of TrustManagers,
     * but with the caveat that it needs to be synchronous and respond via the
     * auth callback hook. This should only be called on the server side of
     * the connection, because it doesn't support the superior async method.
     *
     * See also: SSL_AuthCertificateHook in /usr/include/nss3/ssl.h and
     *           JSSL_SSLFDSyncCertAuthCallback in jss/nss/SSLFDProxy.c
     */
    public static native int ConfigSyncTrustManagerCertAuthCallback(SSLFDProxy fd);

    /**
     * Use an asynchronous bad certificate handler which allows us to approve
     * rejected certificates. This allows us to bypass the hostname check
     * failure caused by the Java socket having no knowledge of the hostname
     * we use for certificate validation; no HostnameVerifier is passed in.
     * As a result, NSS has no value for the hostname and validation will fail.
     *
     * Note: This does NOT work for server-side connections.
     *
     * See also: SSL_BadCertHook in /usr/include/nss3/ssl.h and
     *           JSSL_SSLFDAsyncBadCertCallback in jss/nss/SSLFDProxy.c
     */
    public static native int ConfigAsyncBadCertCallback(SSLFDProxy fd);

    /**
     * Use a synchronous bad certificate handler which allows us to approve
     * rejected certificates. This allows us to bypass the hostname check
     * failure caused by the Java socket having no knowledge of the hostname
     * we use for certificate validation; no HostnameVerifier is passed in.
     * As a result, NSS has no value for the hostname and validation will fail.
     *
     * See also: SSL_BadCertHook in /usr/include/nss3/ssl.h and
     *           JSSL_SSLFDSyncBadCertCallback in jss/nss/SSLFDProxy.c
     */
    public static native int ConfigSyncBadCertCallback(SSLFDProxy fd);

    /**
     * Inform NSS that the asynchronous certificate check handler has
     * completed, allowing us to continue the handshake.
     *
     * This is also used for the async bad certificate handler as well.
     *
     * See also: SSL_AuthCertificateComplete in /usr/include/nss3/ssl.h
     */
    public static native int AuthCertificateComplete(SSLFDProxy fd, int error);

    /**
     * Removes all enabled callbacks.
     */
    public static native void RemoveCallbacks(SSLFDProxy fd);

    /*
     * Enable handshake completion status checking.
     *
     * See also: SSL_HandshakeCallback in /usr/include/nss3/ssl.h
     */
    public static native int EnableHandshakeCallback(SSLFDProxy fd);

    /* Internal methods for querying constants. */
    private static native int getSSLRequestCertificate();
    private static native int getSSLRequireCertificate();
    private static native int getSSLSECSuccess();
    private static native int getSSLSECFailure();
    private static native int getSSLSECWouldBlock();
    private static native int getSSLEnablePostHandshakeAuth();
    private static native int getSSLEnableRenegotiation();
    private static native int getSSLRequireSafeNegotiation();
    private static native int getSSLRenegotiateNever();
    private static native int getSSLRenegotiateUnrestricted();
    private static native int getSSLRenegotiateRequiresXtn();
    private static native int getSSLRenegotiateTransitional();
    private static native int getSSLEnableFallbackSCSV();
    private static native int getSSLRequireNever();
    private static native int getSSLRequireAlways();
    private static native int getSSLRequireFirstHandshake();
    private static native int getSSLRequireNoError();
}
