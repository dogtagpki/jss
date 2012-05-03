/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss.crypto;

/**
 * An X509 Certificate that lives on a PKCS #11 token.
 * Many of the X509Certificates returned by JSS calls are actually
 * TokenCertificates.
 * To find out if an X509Certificate is a TokenCertificate, use 
 *  <code>instanceof</code>.
 */
public interface TokenCertificate extends X509Certificate {

    /**
     * Returns the unique ID of this key.  Unique IDs can be used to match
     * certificates to keys.
     *
     * @see org.mozilla.jss.crypto.PrivateKey#getUniqueID
     * @deprecated This ID is based on an implementation that might change.
     *      If this functionality is required, it should be provided in
     *      another way, such as a function that directly matches a cert and
     *      key.
     */
    public abstract byte[] getUniqueID();

    /**
     * Returns the CryptoToken that owns this certificate. Cryptographic
     * operations with this key may only be performed on the token that
     * owns the key.
     */
    public abstract CryptoToken getOwningToken();
}
