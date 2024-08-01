/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss.crypto;

import java.math.BigInteger;
import java.security.Principal;
import java.security.cert.CertificateEncodingException;

/**
 * Certificates handled by JSS.  All certificates handled by JSS are
 * of this type.
 */
public abstract class X509Certificate
        extends java.security.cert.X509Certificate
        implements InternalCertificate, TokenCertificate {

    ///////////////////////////////////////////////////////////////////////
    // Trust Flags
    // https://github.com/nss-dev/nss/blob/master/lib/certdb/certdb.h
    ///////////////////////////////////////////////////////////////////////

    // CERTDB_TERMINAL_RECORD
    public static final int VALID_PEER        = 1 << 0;

    // CERTDB_TRUSTED
    public static final int TRUSTED_PEER      = 1 << 1;

    // CERTDB_SEND_WARN
    public final static int SEND_WARN         = 1 << 2;

    // CERTDB_VALID_CA
    public static final int VALID_CA          = 1 << 3;

    // CERTDB_TRUSTED_CA
    public static final int TRUSTED_CA        = 1 << 4;

    // CERTDB_NS_TRUSTED_CA
    public final static int NS_TRUSTED_CA     = 1 << 5;

    // CERTDB_USER
    public static final int USER              = 1 << 6;

    // CERTDB_TRUSTED_CLIENT_CA
    public static final int TRUSTED_CLIENT_CA = 1 << 7;

    // CERTDB_INVISIBLE_CA
    public static final int INVISIBLE_CA      = 1 << 8;

    // CERTDB_GOVT_APPROVED_CA
    public static final int GOVT_APPROVED_CA  = 1 << 9;

    ///////////////////////////////////////////////////////////////////////
    // Trust Management
    ///////////////////////////////////////////////////////////////////////

    public static final int SSL               = 0;
    public static final int EMAIL             = 1;
    public static final int OBJECT_SIGNING    = 2;

    /**
     * @return The DER encoding of this certificate.
     * @throws CertificateEncodingException If an error occurred.
     */
    public abstract byte[] getEncoded()
            throws CertificateEncodingException;

    /**
     * @return The nickname of this certificate (could be null).
     */
    public abstract String getNickname();

    /**
     * @return The Public Key from this certificate.
     */
    public abstract java.security.PublicKey getPublicKey();

    /**
     * @return The RFC 1485 ASCII encoding of the Subject Name.
     */
    public abstract Principal
    getSubjectDN();

    /**
     * @return The RFC 1485 ASCII encoding of the issuer's Subject Name.
     */
    public abstract Principal
    getIssuerDN();

    /**
     * @return The serial number of this certificate.
     */
    public abstract BigInteger
    getSerialNumber();

    /**
     * @return the version number of this X.509 certificate.
     * 0 means v1, 1 means v2, 2 means v3.
     */
    public abstract int
    getVersion();

    ///////////////////////////////////////////////////////////////////////
    // Trust Management.  Must only be called on certs that live in the
    // internal database.
    ///////////////////////////////////////////////////////////////////////

    public static boolean isTrustFlagEnabled(int flag, int flags) {
        return (flag & flags) > 0;
    }

    // based on printflags() in secutil.c in NSS
    public static String encodeTrustFlags(int flags) {

        StringBuffer sb = new StringBuffer();

        if (isTrustFlagEnabled(VALID_CA, flags)
                && !isTrustFlagEnabled(TRUSTED_CA, flags)
                && !isTrustFlagEnabled(TRUSTED_CLIENT_CA, flags))
            sb.append("c");

        if (isTrustFlagEnabled(VALID_PEER, flags)
                && !isTrustFlagEnabled(TRUSTED_PEER, flags))
            sb.append("p");

        if (isTrustFlagEnabled(TRUSTED_CA, flags))
            sb.append("C");

        if (isTrustFlagEnabled(TRUSTED_CLIENT_CA, flags))
            sb.append("T");

        if (isTrustFlagEnabled(TRUSTED_PEER, flags))
            sb.append("P");

        if (isTrustFlagEnabled(USER, flags))
            sb.append("u");

        if (isTrustFlagEnabled(SEND_WARN, flags))
            sb.append("w");

        if (isTrustFlagEnabled(INVISIBLE_CA, flags))
            sb.append("I");

        if (isTrustFlagEnabled(GOVT_APPROVED_CA, flags))
            sb.append("G");

        return sb.toString();
    }

    // based on CERT_DecodeTrustString() in certdb.c in NSS
    public static int decodeTrustFlags(String flags) throws Exception {

        int value = 0;

        for (char c : flags.toCharArray()) {
            switch (c) {
            case 'p':
                value = value | VALID_PEER;
                break;
            case 'P':
                value = value | TRUSTED_PEER | VALID_PEER;
                break;
            case 'w':
                value = value | SEND_WARN;
                break;
            case 'c':
                value = value | VALID_CA;
                break;
            case 'T':
                value = value | TRUSTED_CLIENT_CA | VALID_CA;
                break;
            case 'C' :
                value = value | TRUSTED_CA | VALID_CA;
                break;
            case 'u':
                value = value | USER;
                break;
            case 'i':
                value = value | INVISIBLE_CA;
                break;
            case 'g':
                value = value | GOVT_APPROVED_CA;
                break;
            default:
                throw new Exception("Invalid trust flag: " + c);
            }
        }

        return value;
    }

    /**
     * Sets the trust flags for this cert.
     *
     * @param type SSL, EMAIL, or OBJECT_SIGNING.
     * @param trust The trust flags for this type of trust.
     */
    public abstract void setTrust(int type, int trust);

    /**
     * Gets the trust flags for this cert.
     *
     * @param type SSL, EMAIL, or OBJECT_SIGNING.
     * @return The trust flags for this type of trust.
     */
    public abstract int getTrust(int type);

    /**
     * Set the SSL trust flags for this certificate.
     *
     * @param trust A bitwise OR of the trust flags VALID_PEER, VALID_CA,
     *      TRUSTED_CA, USER, and TRUSTED_CLIENT_CA.
     */
    @Override
    public void setSSLTrust(int trust) {
        setTrust(SSL, trust);
    }

    /**
     * Set the email (S/MIME) trust flags for this certificate.
     *
     * @param trust A bitwise OR of the trust flags VALID_PEER, VALID_CA,
     *      TRUSTED_CA, USER, and TRUSTED_CLIENT_CA.
     */
    @Override
    public void setEmailTrust(int trust) {
        setTrust(EMAIL, trust);
    }

    /**
     * Set the object signing trust flags for this certificate.
     *
     * @param trust A bitwise OR of the trust flags VALID_PEER, VALID_CA,
     *      TRUSTED_CA, USER, and TRUSTED_CLIENT_CA.
     */
    @Override
    public void setObjectSigningTrust(int trust) {
        setTrust(OBJECT_SIGNING, trust);
    }

    /**
     * Get the SSL trust flags for this certificate.
     *
     * @return A bitwise OR of the trust flags VALID_PEER, VALID_CA,
     *      TRUSTED_CA, USER, and TRUSTED_CLIENT_CA.
     */
    @Override
    public int getSSLTrust() {
        return getTrust(SSL);
    }

    /**
     * Get the email (S/MIME) trust flags for this certificate.
     *
     * @return A bitwise OR of the trust flags VALID_PEER, VALID_CA,
     *      TRUSTED_CA, USER, and TRUSTED_CLIENT_CA.
     */
    @Override
    public int getEmailTrust() {
        return getTrust(EMAIL);
    }

    /**
     * Get the object signing trust flags for this certificate.
     *
     * @return A bitwise OR of the trust flags VALID_PEER, VALID_CA,
     *      TRUSTED_CA, USER, and TRUSTED_CLIENT_CA.
     */
    @Override
    public int getObjectSigningTrust() {
        return getTrust(OBJECT_SIGNING);
    }

    public String getTrustFlags() {

        StringBuilder sb = new StringBuilder();

        sb.append(encodeTrustFlags(getSSLTrust()));
        sb.append(",");
        sb.append(encodeTrustFlags(getEmailTrust()));
        sb.append(",");
        sb.append(encodeTrustFlags(getObjectSigningTrust()));

        return sb.toString();
    }

    public void setTrustFlags(String trustFlags) throws Exception {

        String[] flags = trustFlags.split(",", -1); // don't remove empty string
        if (flags.length < 3) throw new Exception("Invalid trust flags: " + trustFlags);

        setSSLTrust(decodeTrustFlags(flags[0]));
        setEmailTrust(decodeTrustFlags(flags[1]));
        setObjectSigningTrust(decodeTrustFlags(flags[2]));
    }
}
