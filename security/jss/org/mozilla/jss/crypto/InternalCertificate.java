/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.crypto;

/**
 * Certificates residing in the internal database.  Their trust flags
 * can be viewed and modified. Other types of certificates do not
 * have trust flags.
 */
public interface InternalCertificate extends X509Certificate
{
    ////////////////////////////////////////////////////
    // Trust manipulation
    ////////////////////////////////////////////////////
    public static final int VALID_PEER          = (1<<0);
    public static final int TRUSTED_PEER        = (1<<1); // CERTDB_TRUSTED
    public static final int VALID_CA            = (1<<3);
    public static final int TRUSTED_CA          = (1<<4);
    public static final int USER                = (1<<6);
    public static final int TRUSTED_CLIENT_CA   = (1<<7);

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
