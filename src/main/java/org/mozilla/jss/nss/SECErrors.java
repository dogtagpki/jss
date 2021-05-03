package org.mozilla.jss.nss;

/**
 * This class provides access to useful NSS errors, getting their values from
 * a JNI call. Note that it *isn't* an enum as the NSS wrappers return int.
 * This saves us from having to wrap every NSS error in a class instance only
 * to later unwrap it to make any useful calls.
 */

public class SECErrors {
    /**
     * Improperly encoded DER message.
     *
     * See also: SEC_ERROR_BAD_DER in /usr/include/nss3/secerr.h
     */
    public static final int BAD_DER = getBadDER();

    /**
     * Expired Certificate.
     *
     * See also: SEC_ERROR_EXPIRED_CERTIFICATE in /usr/include/nss3/secerr.h
     */
    public static final int EXPIRED_CERTIFICATE = getExpiredCertificate();

    /**
     * Certificate valid start date is in the future.
     *
     * See also: SEC_ERROR_CERT_NOT_VALID in /usr/include/nss3/secerr.h
     */
    public static final int CERT_NOT_VALID = getCertNotValid();

    /**
     * Certificate was revoked by the OCSP responder.
     *
     * See also: SEC_ERROR_REVOKED_CERTIFICATE_OCSP in /usr/include/nss3/secerr.h
     */
    public static final int REVOKED_CERTIFICATE_OCSP = getRevokedCertificateOCSP();

    /**
     * Certificate was revoked by the issuer.
     *
     * See also: SEC_ERROR_REVOKED_CERTIFICATE in /usr/include/nss3/secerr.h
     */
    public static final int REVOKED_CERTIFICATE = getRevokedCertificate();

    /**
     * Certificate was signed by an untrusted issuer.
     *
     * See also: SEC_ERROR_UNTRUSTED_ISSUER in /usr/include/nss3/secerr.h
     */
    public static final int UNTRUSTED_ISSUER = getUntrustedIssuer();

    /**
     * Certificate was marked as untrusted.
     *
     * See also: SEC_ERROR_UNTRUSTED_CERT in /usr/include/nss3/secerr.h
     */
    public static final int UNTRUSTED_CERT = getUntrustedCert();

    private static native int getBadDER();
    private static native int getExpiredCertificate();
    private static native int getCertNotValid();
    private static native int getRevokedCertificateOCSP();
    private static native int getRevokedCertificate();
    private static native int getUntrustedIssuer();
    private static native int getUntrustedCert();
}
