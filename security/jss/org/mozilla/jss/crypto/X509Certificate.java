/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss.crypto;

import java.security.Principal;
import java.math.BigInteger;

/**
 * Certificates handled by JSS.  All certificates handled by JSS are
 * of this type.
 */
public interface X509Certificate
{
    /**
     * Returns the DER encoding of this certificate.
     */
    public byte[] getEncoded()
		throws java.security.cert.CertificateEncodingException;

    /**
     * Returns the possibly-null nickname of this certificate.
     */
    public abstract String getNickname();

    /**
     * Extracts the Public Key from this certificate.
     */
    public abstract java.security.PublicKey getPublicKey();

    /**
     * Returns the RFC 1485 ASCII encoding of the Subject Name.
     */
    public abstract Principal
    getSubjectDN();

    /**
     * Returns the RFC 1485 ASCII encoding of the issuer's Subject Name.
     */
    public abstract Principal
    getIssuerDN();

    /**
     * Returns the serial number of this certificate.
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
