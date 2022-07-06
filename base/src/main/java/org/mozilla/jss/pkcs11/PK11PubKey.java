/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkcs11;

import org.mozilla.jss.crypto.InvalidKeyFormatException;
import org.mozilla.jss.crypto.PrivateKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PK11PubKey extends org.mozilla.jss.pkcs11.PK11Key
	implements java.security.PublicKey {

    private static final long serialVersionUID = 1L;

    protected PK11PubKey(byte[] pointer) {
        assert(pointer!=null);
        keyProxy = new PublicKeyProxy(pointer);
    }

	/**
	 * Make sure this key lives on the given token.
	 */
	public native void verifyKeyIsOnToken(PK11Token token)
		throws org.mozilla.jss.crypto.NoSuchItemOnTokenException;

    public native KeyType getKeyType();

    @Override
    public String getAlgorithm() {
        return getKeyType().toString();
    }

    /**
     * Creates a PK11PubKey from its raw form. The raw form is a DER encoding
     * of the public key.  For example, this is what is stored in a
     * SubjectPublicKeyInfo.
     *
     * @param type The type of private key to be decoded.
     * @param rawKey The bytes of the raw key.
     * @exception InvalidKeyFormatException If the raw key could not be
     *      decoded.
     * @deprecated This method works for RSA keys but not DSA or EC keys. Use
     *      fromSPKI() instead.
     * @see #fromSPKI(byte[])
     */
    @Deprecated
    public static PK11PubKey fromRaw(PrivateKey.Type type, byte[] rawKey)
        throws InvalidKeyFormatException
    {
        if( type != PrivateKey.Type.RSA ) {
            throw new InvalidKeyFormatException(
                "fromRaw() is broken for DSA keys. Use fromSPKI() instead.");
        }
        return fromRawNative( type.getPKCS11Type(), rawKey );
    }

    /**
     * param type The PKCS #11 type of the key (CKK_).
     */
    private static native PK11PubKey fromRawNative(int type, byte[] rawKey)
        throws InvalidKeyFormatException;

    /**
     * Creates a PK11PubKey from a SubjectPublicKeyInfo.
     *
     * @param spki The BER-encoded SubjectPublicKeyInfo.
     * @exception InvalidKeyFormatException If the SPKI could not be
     *      decoded.
     */
    public static native PK11PubKey fromSPKI(byte[] spki)
        throws InvalidKeyFormatException;

    /**
     * deprecated Use fromRawNative instead.
     */
    private static native PK11PubKey RSAFromRaw(byte[] rawKey);

    /**
     * deprecated Use fromRawNative instead.
     */
    private static native PK11PubKey DSAFromRaw(byte[] rawKey);

    /**
     * Returns a DER-encoded SubjectPublicKeyInfo representing this key.
     */
    @Override
    public native byte[] getEncoded();

    /**
     *  The name of the primary encoding format of this key.  The primary
     *  encoding format is X.509 <i>SubjectPublicKeyInfo</i>, and the name
     *  is "X.509".
     */
    @Override
    public String getFormat() {
        return "X.509";
    }
}

class PublicKeyProxy extends KeyProxy {

    public static Logger logger = LoggerFactory.getLogger(PublicKeyProxy.class);

    public PublicKeyProxy(byte[] pointer) {
        super(pointer);
    }

    @Override
    protected native void releaseNativeResources();
}
