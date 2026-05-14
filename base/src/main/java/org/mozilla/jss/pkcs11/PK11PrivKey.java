/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkcs11;

import java.math.BigInteger;
import java.security.KeyException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;

import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.TokenException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PK11PrivKey extends org.mozilla.jss.pkcs11.PK11Key
	implements PrivateKey {

    private static final long serialVersionUID = 1L;

    private PK11PrivKey() { }

    protected PK11PrivKey(byte[] pointer) {
        assert(pointer!=null);
        keyProxy = new PrivateKeyProxy(pointer);
    }

	/**
	 * Make sure this key lives on the given token.
	 */
	public native void verifyKeyIsOnToken(PK11Token token)
		throws org.mozilla.jss.crypto.NoSuchItemOnTokenException;

    /**
     * Returns a new CryptoToken where this key resides.
     *
     * @return The PK11Token that owns this key.
     */
    @Override
    public native CryptoToken getOwningToken();

    @Override
    public native byte[] getUniqueID() throws TokenException;

    public native KeyType getKeyType();
    private native long getMLKeyParam();

    @Override
    public PrivateKey.Type getType() throws KeyException {
        KeyType kt = getKeyType();
        if( kt == KeyType.RSA ) {
            return PrivateKey.Type.RSA;
        } else if (kt == KeyType.DSA) {
            return PrivateKey.Type.DSA;
        } else if (kt == KeyType.MLDSA) {
            long keyParam = getMLKeyParam();
            if (keyParam == PKCS11Constants.CKP_ML_DSA_44) return PrivateKey.Type.MLDSA44;
            if (keyParam == PKCS11Constants.CKP_ML_DSA_65) return PrivateKey.Type.MLDSA65;
            if (keyParam == PKCS11Constants.CKP_ML_DSA_87) return PrivateKey.Type.MLDSA87;
            throw new KeyException("Unsupported ML-DSA parameter set: " + keyParam);
        } else if (kt == KeyType.MLKEM) {
            long keyParam = getMLKeyParam();
            if (keyParam == PKCS11Constants.CKP_ML_KEM_512) return PrivateKey.Type.MLKEM512;
            if (keyParam == PKCS11Constants.CKP_ML_KEM_768) return PrivateKey.Type.MLKEM768;
            if (keyParam == PKCS11Constants.CKP_ML_KEM_1024) return PrivateKey.Type.MLKEM1024;
            throw new KeyException("Unsupported ML-KEM parameter set: " + keyParam);
        } else {
            assert(kt == KeyType.EC);
            return PrivateKey.Type.EC;
	}
    }

    @Override
    public String getAlgorithm() {
        return getKeyType().toString();
    }

    @Override
    public AlgorithmParameterSpec getParams() {
        Type t = null;
        try {
            t = getType();
        } catch (KeyException ex) {
            throw new PK11Exception("Private key agorithm not recogniesed", ex);
        }
        if (t == Type.MLDSA44 || t == Type.MLDSA65 || t == Type.MLDSA87 ||
                t == Type.MLKEM512 || t == Type.MLKEM768 || t == Type.MLKEM1024) {
            return new NamedParameterSpec(t.toString());
        }
        return null;
    }

   /**
     * Returns the size in bits of the modulus of an RSA Private key.
     * Returns -1 for other types of keys.
     */
    @Override
    public native int getStrength();

    /**
     * Returns the corresponding public key from a private key instance.
     */
    public native PK11PubKey getPublicKey();

    /**
     * Sets the private key PRBool pkcs11IsTemp property.
     * Use with care
     */
    public native void setTemporary(boolean isTemporary);

    /**
     * Imports a PrivateKeyInfo, storing it as a temporary PrivateKey
     * on the given token.
     * The key will be a temporary (session) key until it is imported
     * into a KeyStore, at which point it will be made a permanent (token)
     * object.
     */
    public static PK11PrivKey
    fromPrivateKeyInfo(PKCS8EncodedKeySpec spec, CryptoToken token)
        throws TokenException
    {
        return fromPrivateKeyInfo(spec.getEncoded(), token);
    }

    /**
     * Imports a PrivateKeyInfo, storing it as a temporary PrivateKey
     * on the given token.
     * The key will be a temporary (session) key until it is imported
     * into a KeyStore, at which point it will be made a permanent (token)
     * object.
     */
    public static PK11PrivKey
    fromPrivateKeyInfo(byte[] pki, CryptoToken token) throws TokenException {
        return fromPrivateKeyInfo(pki, token, null);
    }

    /**
     * Imports a PrivateKeyInfo, storing it as a temporary PrivateKey
     * on the given token.
     * The key will be a temporary (session) key until it is imported
     * into a KeyStore, at which point it will be made a permanent (token)
     * object.
     * @param publicValue An encoding of the public key, as used by the NSS
     *  pk11wrap code. Don't use this unless you know what you're doing.
     */
    public static native PK11PrivKey
    fromPrivateKeyInfo(byte[] pki, CryptoToken token, byte[] publicValue)
        throws TokenException;

    protected DSAParameterSpec
    getDSAParams() throws TokenException {
        byte[][] pqgArray = getDSAParamsNative();

        return new PK11DSAParams(
            new BigInteger(1, pqgArray[0]),
            new BigInteger(1, pqgArray[1]),
            new BigInteger(1, pqgArray[2])
        );
    }

    private native byte[][]
    getDSAParamsNative() throws TokenException;


}

class PrivateKeyProxy extends KeyProxy {

    public static Logger logger = LoggerFactory.getLogger(PrivateKeyProxy.class);

    public PrivateKeyProxy(byte[] pointer) {
        super(pointer);
    }

    @Override
    protected native void releaseNativeResources();
}
