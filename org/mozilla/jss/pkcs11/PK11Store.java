/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkcs11;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.*;
import org.mozilla.jss.util.*;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.util.Vector;

public final class PK11Store implements CryptoStore {

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

    public synchronized PrivateKey[]
    getPrivateKeys() throws TokenException {
        Vector keys = new Vector();
        putKeysInVector(keys);
        PrivateKey[] array = new PrivateKey[keys.size()];
        keys.copyInto( (Object[]) array );
        return array;
    }

    public synchronized SymmetricKey[]
    getSymmetricKeys() throws TokenException {

        Vector keys = new Vector();
        putSymKeysInVector(keys);
        SymmetricKey[] array = new SymmetricKey[keys.size()];
        keys.copyInto( (Object[]) array);
        return array;
    }

    protected native void putKeysInVector(Vector keys) throws TokenException;
    
    protected native void putSymKeysInVector(Vector symKeys) throws TokenException;


    public native void deletePrivateKey(PrivateKey key)
        throws NoSuchItemOnTokenException, TokenException;

    public byte[] getEncryptedPrivateKeyInfo(
            X509Certificate cert,
            PBEAlgorithm pbeAlg,
            Password pw,
            int iteration)
            throws CryptoManager.NotInitializedException,
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
        Vector certs = new Vector();
        putCertsInVector(certs);
        X509Certificate[] array = new X509Certificate[certs.size()];
        certs.copyInto( (Object[]) array );
        return array;
    }
    protected native void putCertsInVector(Vector certs) throws TokenException;

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
