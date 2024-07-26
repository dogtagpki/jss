/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.crypto;

import org.mozilla.jss.pkcs11.PK11Cert;

/**
 * Certificates residing in the internal database.  Their trust flags
 * can be viewed and modified. Other types of certificates do not
 * have trust flags.
 */
public interface InternalCertificate
{
    /**
     * @deprecated Use PK11Cert.VALID_PEER instead.
     */
    @Deprecated
    public static final int VALID_PEER          = PK11Cert.VALID_PEER;

    /**
     * @deprecated Use PK11Cert.TRUSTED_PEER instead.
     */
    @Deprecated
    public static final int TRUSTED_PEER        = PK11Cert.TRUSTED_PEER;

    /**
     * @deprecated Use PK11Cert.VALID_CA instead.
     */
    @Deprecated
    public static final int VALID_CA            = PK11Cert.VALID_CA;

    /**
     * @deprecated Use PK11Cert.TRUSTED_CA instead.
     */
    @Deprecated
    public static final int TRUSTED_CA          = PK11Cert.TRUSTED_CA;

    /**
     * @deprecated Use PK11Cert.USER instead.
     */
    @Deprecated
    public static final int USER                = PK11Cert.USER;

    /**
     * @deprecated Use PK11Cert.TRUSTED_CLIENT_CA instead.
     */
    @Deprecated
    public static final int TRUSTED_CLIENT_CA   = PK11Cert.TRUSTED_CLIENT_CA;

    /**
     * Set the SSL trust flags for this certificate.
     *
     * @param trust A bitwise OR of the trust flags VALID_PEER, VALID_CA,
     *      TRUSTED_CA, USER, and TRUSTED_CLIENT_CA.
     */
    public abstract void setSSLTrust(int trust);

    /**
     * Set the email (S/MIME) trust flags for this certificate.
     *
     * @param trust A bitwise OR of the trust flags VALID_PEER, VALID_CA,
     *      TRUSTED_CA, USER, and TRUSTED_CLIENT_CA.
     */
    public abstract void setEmailTrust(int trust);

    /**
     * Set the object signing trust flags for this certificate.
     *
     * @param trust A bitwise OR of the trust flags VALID_PEER, VALID_CA,
     *      TRUSTED_CA, USER, and TRUSTED_CLIENT_CA.
     */
    public abstract void setObjectSigningTrust(int trust);

    /**
     * Get the SSL trust flags for this certificate.
     *
     * @return A bitwise OR of the trust flags VALID_PEER, VALID_CA,
     *      TRUSTED_CA, USER, and TRUSTED_CLIENT_CA.
     */
    public abstract int getSSLTrust();

    /**
     * Get the email (S/MIME) trust flags for this certificate.
     *
     * @return A bitwise OR of the trust flags VALID_PEER, VALID_CA,
     *      TRUSTED_CA, USER, and TRUSTED_CLIENT_CA.
     */
    public abstract int getEmailTrust();

    /**
     * Get the object signing trust flags for this certificate.
     *
     * @return A bitwise OR of the trust flags VALID_PEER, VALID_CA,
     *      TRUSTED_CA, USER, and TRUSTED_CLIENT_CA.
     */
    public abstract int getObjectSigningTrust();
}
