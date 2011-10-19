/* ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is the Netscape Security Services for Java.
 *
 * The Initial Developer of the Original Code is
 * Netscape Communications Corporation.
 * Portions created by the Initial Developer are Copyright (C) 1998-2000
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either the GNU General Public License Version 2 or later (the "GPL"), or
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the MPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the MPL, the GPL or the LGPL.
 *
 * ***** END LICENSE BLOCK ***** */

package org.mozilla.jss.pkcs11;

import org.mozilla.jss.crypto.*;
import org.mozilla.jss.util.*;
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
    public native void
    importPrivateKey(  byte[] key,
                       PrivateKey.Type type       )
        throws TokenException,KeyAlreadyImportedException;

    public synchronized PrivateKey[]
    getPrivateKeys() throws TokenException {
        Vector keys = new Vector();
        putKeysInVector(keys);
        PrivateKey[] array = new PrivateKey[keys.size()];
        keys.copyInto( (Object[]) array );
        return array;
    }
    protected native void putKeysInVector(Vector keys) throws TokenException;


    public native void deletePrivateKey(PrivateKey key)
        throws NoSuchItemOnTokenException, TokenException;

    public native byte[] getEncryptedPrivateKeyInfo(X509Certificate cert,
        PBEAlgorithm pbeAlg, Password pw, int iteration);

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
