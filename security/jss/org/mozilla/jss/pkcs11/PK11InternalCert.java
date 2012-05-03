/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkcs11;

import org.mozilla.jss.crypto.*;
import org.mozilla.jss.util.*;
import java.security.*;
import java.security.cert.*;
import java.util.*;
import java.math.BigInteger;

/**
 * A certificate that lives in the internal cert database.
 */
public class PK11InternalCert extends PK11Cert
        implements InternalCertificate
{
    ///////////////////////////////////////////////////////////////////////
    // Trust Management.  This is all package stuff because it can only
    // be called from PK11InternalCert.
    ///////////////////////////////////////////////////////////////////////
    public static final int SSL = 0;
    public static final int EMAIL = 1;
    public static final int OBJECT_SIGNING=2;

    /**
     * Set the SSL trust flags for this certificate.
     *
     * @param trust A bitwise OR of the trust flags VALID_PEER, VALID_CA,
     *      TRUSTED_CA, USER, and TRUSTED_CLIENT_CA.
     */
    public void setSSLTrust(int trust)
    {
        super.setTrust(SSL, trust);
    }

    /**
     * Set the email (S/MIME) trust flags for this certificate.
     *
     * @param trust A bitwise OR of the trust flags VALID_PEER, VALID_CA,
     *      TRUSTED_CA, USER, and TRUSTED_CLIENT_CA.
     */
    public void setEmailTrust(int trust)
    {
        super.setTrust(EMAIL, trust);
    }

    /**
     * Set the object signing trust flags for this certificate.
     *
     * @param trust A bitwise OR of the trust flags VALID_PEER, VALID_CA,
     *      TRUSTED_CA, USER, and TRUSTED_CLIENT_CA.
     */
    public void setObjectSigningTrust(int trust)
    {
        super.setTrust(OBJECT_SIGNING, trust);
    }

    /**
     * Get the SSL trust flags for this certificate.
     *
     * @return A bitwise OR of the trust flags VALID_PEER, VALID_CA,
     *      TRUSTED_CA, USER, and TRUSTED_CLIENT_CA.
     */
    public int getSSLTrust()
    {
        return super.getTrust(SSL);
    }

    /**
     * Get the email (S/MIME) trust flags for this certificate.
     *
     * @return A bitwise OR of the trust flags VALID_PEER, VALID_CA,
     *      TRUSTED_CA, USER, and TRUSTED_CLIENT_CA.
     */
    public int getEmailTrust()
    {
        return super.getTrust(EMAIL);
    }

    /**
     * Get the object signing trust flags for this certificate.
     *
     * @return A bitwise OR of the trust flags VALID_PEER, VALID_CA,
     *      TRUSTED_CA, USER, and TRUSTED_CLIENT_CA.
     */
    public int getObjectSigningTrust()
    {
        return super.getTrust(OBJECT_SIGNING);
    }

	/////////////////////////////////////////////////////////////
	// Construction
	/////////////////////////////////////////////////////////////
    PK11InternalCert(byte[] certPtr, byte[] slotPtr, String nickname) {
        super(certPtr, slotPtr, nickname);
    }
}
