/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkcs11;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Vector;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.NotInitializedException;
import org.mozilla.jss.crypto.Algorithm;
import org.mozilla.jss.crypto.CryptoStore;
import org.mozilla.jss.crypto.KeyAlreadyImportedException;
import org.mozilla.jss.crypto.KeyGenerator;
import org.mozilla.jss.crypto.NoSuchItemOnTokenException;
import org.mozilla.jss.crypto.ObjectNotFoundException;
import org.mozilla.jss.crypto.PBEAlgorithm;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.util.Assert;
import org.mozilla.jss.util.Password;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class PK11Store implements CryptoStore {

    public static Logger logger = LoggerFactory.getLogger(PK11Store.class);

    ////////////////////////////////////////////////////////////
    // Private Keys
    ////////////////////////////////////////////////////////////
    /**
     * Imports a raw private key into this token.
     *
     * @param key The private key.
     * @exception TokenException If the key cannot be imported to this token.
     * @exception KeyAlreadyImportedException If the key already on this token.
     */
    public PrivateKey
    importPrivateKey(byte[] key, PrivateKey.Type type)
            throws TokenException,KeyAlreadyImportedException {
        return importPrivateKey(key, type, false);
    }

    public native PrivateKey
    importPrivateKey(
        byte[] key, PrivateKey.Type type, boolean temporary)
        throws TokenException,KeyAlreadyImportedException;

    public synchronized PrivateKey[] getPrivateKeys() throws TokenException {

        ArrayList<PrivateKey> list = new ArrayList<>();
        loadPrivateKeys(list);

        PrivateKey[] array = new PrivateKey[list.size()];
        list.toArray(array);

        return array;
    }

    protected native void loadPrivateKeys(Collection<PrivateKey> privateKeys) throws TokenException;

    public synchronized PublicKey[] getPublicKeys() throws TokenException {

        ArrayList<PublicKey> list = new ArrayList<>();
        loadPublicKeys(list);

        PublicKey[] array = new PublicKey[list.size()];
        list.toArray(array);

        return array;
    }

    protected native void loadPublicKeys(Collection<PublicKey> privateKeys) throws TokenException;

    public PublicKey findPublicKey(PrivateKey privateKey) throws TokenException, ObjectNotFoundException {

        // NSS does not provide a function to find the public key of a private key,
        // so it has to be done manually.

        if (privateKey instanceof RSAPrivateKey) {

            logger.debug("PKCS11Store: searching for RSA public key");

            RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) privateKey;
            BigInteger modulus = rsaPrivateKey.getModulus();

            // Find the RSA public key by comparing the modulus.

            for (PublicKey publicKey : getPublicKeys()) {

                if (!(publicKey instanceof RSAPublicKey)) {
                    // not an RSA public key
                    continue;
                }

                RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
                if (!modulus.equals(rsaPublicKey.getModulus())) {
                    // modulus doesn't match
                    continue;
                }

                logger.debug("PKCS11Store: found RSA public key");
                return publicKey;
            }

        } else {
            // TODO: add support for non-RSA keys
        }

        throw new ObjectNotFoundException("Unable to find public key");
    }

    public synchronized SymmetricKey[]
    getSymmetricKeys() throws TokenException {

        Vector<SymmetricKey> keys = new Vector<>();
        putSymKeysInVector(keys);
        SymmetricKey[] array = new SymmetricKey[keys.size()];
        keys.copyInto( array);
        return array;
    }

    protected native void putSymKeysInVector(Vector<SymmetricKey> symKeys) throws TokenException;


    public native void deletePrivateKey(PrivateKey privateKey)
        throws NoSuchItemOnTokenException, TokenException;

    public native void deletePublicKey(PublicKey publicKey)
            throws NoSuchItemOnTokenException, TokenException;

    public byte[] getEncryptedPrivateKeyInfo(
            X509Certificate cert,
            PBEAlgorithm pbeAlg,
            Password pw,
            int iteration)
            throws NotInitializedException,
                ObjectNotFoundException, TokenException {
        return getEncryptedPrivateKeyInfo(
            null,
            pw,
            pbeAlg,
            iteration,
            CryptoManager.getInstance().findPrivKeyByCert(cert)
        );
    }

    public native byte[] getEncryptedPrivateKeyInfo(
        KeyGenerator.CharToByteConverter conv,
        Password pw,
        Algorithm alg,
        int n,
        PrivateKey k);

    public native void importEncryptedPrivateKeyInfo(
        KeyGenerator.CharToByteConverter conv,
        Password pw,
        String nickname,
        PublicKey pubKey,
        byte[] epkiBytes);

    ////////////////////////////////////////////////////////////
    // Certs
    ////////////////////////////////////////////////////////////

    public X509Certificate[]
    getCertificates() throws TokenException
    {
        Vector<X509Certificate> certs = new Vector<>();
        putCertsInVector(certs);
        X509Certificate[] array = new X509Certificate[certs.size()];
        certs.copyInto( array );
        return array;
    }
    protected native void putCertsInVector(Vector<X509Certificate> certs) throws TokenException;

    /**
     * Deletes the specified certificate and its associated private
     * key from the store.
     *
     * @param cert certificate to be deleted
     * @exception NoSuchItemOnTokenException If the certificate not found
     * @exception TokenException General token error
     */
	// Currently have to use PK11_DeleteTokenObject + PK11_FindObjectForCert
	// or maybe SEC_DeletePermCertificate.
    public native void deleteCert(X509Certificate cert)
        throws NoSuchItemOnTokenException, TokenException;

    /**
     * Deletes the specified certificate from the store.
     *
     * @param cert certificate to be deleted
     * @exception NoSuchItemOnTokenException If the certificate not found
     * @exception TokenException General token error
     */
    public native void deleteCertOnly(X509Certificate cert)
        throws NoSuchItemOnTokenException, TokenException;

	////////////////////////////////////////////////////////////
	// Construction
	////////////////////////////////////////////////////////////
    protected boolean updated;
	public PK11Store(TokenProxy proxy) {
        Assert._assert(proxy!=null);
		this.storeProxy = proxy;
	}

	protected PK11Store() { }

	////////////////////////////////////////////////////////////
	// Private data
	////////////////////////////////////////////////////////////
	protected TokenProxy storeProxy;
}
