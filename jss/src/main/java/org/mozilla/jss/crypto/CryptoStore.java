/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.crypto;

import java.security.PublicKey;

import org.mozilla.jss.NotInitializedException;
import org.mozilla.jss.util.Password;

/**
 * This is an interface for a permanent repository of cryptographic objects,
 * such as keys, certs, and passwords.
 */
public interface CryptoStore {

    ////////////////////////////////////////////////////////////
    // Private Keys
    ////////////////////////////////////////////////////////////

    /**
     * Imports a raw private key into this token (permanently).
     *
     * @param key The private key.
     * @exception TokenException If the key cannot be imported to this token.
     * @exception KeyAlreadyImportedException If the key already exists on this token.
     */
    public PrivateKey
    importPrivateKey(  byte[] key,
                       PrivateKey.Type type       )
        throws TokenException, KeyAlreadyImportedException;

    /**
     * Imports a raw private key into this token.
     *
     * @param key The private key.
     * @param temporary Whether the key should be temporary.
     * @exception TokenException If the key cannot be imported to this token.
     * @exception KeyAlreadyImportedException If the key already exists on this token.
     */
    public PrivateKey
    importPrivateKey(  byte[] key,
                       PrivateKey.Type type, boolean temporary)
        throws TokenException, KeyAlreadyImportedException;


    /**
     * Returns all private keys stored on this token.
     *
     * @return An array of all private keys stored on this token.
     * @exception TokenException If an error occurs on the token while
     *      gathering the keys.
     */
    public PrivateKey[] getPrivateKeys() throws TokenException;

    /**
     * Returns all public keys stored on this token.
     *
     * @return An array of all public keys stored on this token.
     * @exception TokenException If an error occurs on the token while
     *      gathering the keys.
     */
    public PublicKey[] getPublicKeys() throws TokenException;

    /**
     * Returns the public key corresponding to the private key.
     *
     * @param privateKey
     * @return The corresponding public key.
     * @throws ObjectNotFoundException If the corresponding public key is not found.
     * @throws TokenException If an error occurs on the token.
     */
    public PublicKey findPublicKey(PrivateKey privateKey)
            throws ObjectNotFoundException, TokenException;

    /**
     * Returns all symmetric keys stored on this token.
     *
     * @return An array of all symmetric keys stored on this token.
     * @exception TokenException If an error occurs on the token while
     *      gathering the keys.
     */
    public SymmetricKey[] getSymmetricKeys() throws TokenException;

    /**
     * Permanently deletes a private key from the token.
     *
     * @param privateKey A private key to be permanently deleted.
     * @exception NoSuchItemOnTokenException If the given private key does
     *      not reside on this token.
     * @exception TokenException If an error occurs on the token while
     *      deleting the key.
     */
    public void deletePrivateKey(PrivateKey privateKey)
        throws NoSuchItemOnTokenException, TokenException;

    /**
     * Permanently deletes a public key from the token.
     *
     * @param publicKey A public key to be permanently deleted.
     * @exception NoSuchItemOnTokenException If the given public key does
     *      not reside on this token.
     * @exception TokenException If an error occurs on the token while
     *      deleting the key.
     */
    public void deletePublicKey(PublicKey publicKey)
            throws NoSuchItemOnTokenException, TokenException;

    /**
     * Get an encrypted private key for the given cert.
     *
     * @param cert Certificate of key to be exported
     * @param pbeAlg The PBEAlgorithm to use
     * @param pw The password to encrypt with
     * @param iteration Iteration count; default of 2000 if le 0
     */
    public byte[] getEncryptedPrivateKeyInfo(X509Certificate cert,
        PBEAlgorithm pbeAlg, Password pw, int iteration)
        throws NotInitializedException,
            ObjectNotFoundException, TokenException;

    /**
     * Get an encrypted private key, with optional password
     * conversion.
     *
     * @param conv Password converter.  If null, pw.getByteCopy()
     *             will be used to get password bytes.
     * @param pw The password
     * @param alg The encryption algorithm
     * @param n Iteration count; default of 2000 if le 0
     * @param k The private key
     */
    public byte[] getEncryptedPrivateKeyInfo(
        KeyGenerator.CharToByteConverter conv,
        Password pw,
        Algorithm alg,
        int n,
        PrivateKey k);

    /**
     * @param conv Password converter.  If null, pw.getByteCopy()
     *             will be used to get password bytes.
     * @param pw The password
     * @param nickname Nickname to use for private key
     * @param pubKey Public key corresponding to private key
     */
    public void importEncryptedPrivateKeyInfo(
        KeyGenerator.CharToByteConverter conv,
        Password pw,
        String nickname,
        PublicKey pubKey,
        byte[] epkiBytes);

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
    public X509Certificate[] getCertificates() throws TokenException;

    /**
     * Deletes a certificate and the corresponding keys.
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

    /**
     * Deletes a certificate without deleting the corresponding keys.
     *
     * @param cert A certificate to be deleted from this token. The cert
     *      must actually reside on this token.
     * @exception NoSuchItemOnTokenException If the given cert does not
     *      reside on this token.
     * @exception TokenException If an error occurred on the token while
     *      deleting the certificate.
     */
    public void deleteCertOnly(X509Certificate cert)
            throws NoSuchItemOnTokenException, TokenException;
}
