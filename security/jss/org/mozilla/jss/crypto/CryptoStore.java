/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.crypto;

import org.mozilla.jss.util.*;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.io.Serializable;

/**
 * This is an interface for a permanent repository of cryptographic objects,
 * such as keys, certs, and passwords.
 */
public interface CryptoStore {

    ////////////////////////////////////////////////////////////
    // Private Keys
    ////////////////////////////////////////////////////////////

    /**
     * Imports a raw private key into this token.
     *
     * @param key The private key.
     * @exception TokenException If the key cannot be imported to this token.
     * @exception KeyAlreadyImportedException If the key already exists on this token.
     */
    public void
    importPrivateKey(  byte[] key,
                       PrivateKey.Type type       )
        throws TokenException, KeyAlreadyImportedException;


    /**
     * Returns all private keys stored on this token.
     *
     * @return An array of all private keys stored on this token.
     * @exception TokenException If an error occurs on the token while
     *      gathering the keys.
     */
    public PrivateKey[]
    getPrivateKeys() throws TokenException;

    /**
     * Deletes the given PrivateKey from the CryptoToken.
     * This is a very dangerous call: it deletes the key from the underlying
     * token. After calling this, the PrivateKey passed in must no longer
     * be used, or a TokenException will occur.
     *
     * @param key A PrivateKey to be permanently deleted.  It must reside
     *      on this token.
     * @exception NoSuchItemOnTokenException If the given private key does 
     *      not reside on this token.
     * @exception TokenException If an error occurs on the token while
     *      deleting the key.
     */
    public void deletePrivateKey(org.mozilla.jss.crypto.PrivateKey key)
        throws NoSuchItemOnTokenException, TokenException;


    public byte[] getEncryptedPrivateKeyInfo(X509Certificate cert,
        PBEAlgorithm pbeAlg, Password pw, int iteration);

    ////////////////////////////////////////////////////////////
    // Certs
    ////////////////////////////////////////////////////////////
    /**
     * Returns all user certificates stored on this token. A user certificate
     *      is one that has a matching private key.
     *
     * @return An array of all user certificates present on this token.
     * @exception TokenException If an error occurs on the token while
     *      gathering the certificates.
     */
    public X509Certificate[]
    getCertificates() throws TokenException;

    /**
     * Deletes a certificate from a token.
     *
     * @param cert A certificate to be deleted from this token. The cert
     *      must actually reside on this token.
     * @exception NoSuchItemOnTokenException If the given cert does not
     *      reside on this token.
     * @exception TokenException If an error occurred on the token while
     *      deleting the certificate.
     */
    public void deleteCert(X509Certificate cert)
        throws NoSuchItemOnTokenException, TokenException;
}
