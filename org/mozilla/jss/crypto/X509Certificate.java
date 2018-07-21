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
public interface X509Certificate
{
    /**
     * @return The DER encoding of this certificate.
     * @throws CertificateEncodingException If an error occurred.
     */
    public byte[] getEncoded()
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

}
