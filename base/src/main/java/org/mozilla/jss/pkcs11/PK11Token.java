/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkcs11;

import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

import org.mozilla.jss.crypto.Algorithm;
import org.mozilla.jss.crypto.AlreadyInitializedException;
import org.mozilla.jss.crypto.Cipher;
import org.mozilla.jss.crypto.CryptoStore;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.DigestAlgorithm;
import org.mozilla.jss.crypto.EncryptionAlgorithm;
import org.mozilla.jss.crypto.JSSMessageDigest;
import org.mozilla.jss.crypto.KeyGenAlgorithm;
import org.mozilla.jss.crypto.KeyGenerator;
import org.mozilla.jss.crypto.KeyPairAlgorithm;
import org.mozilla.jss.crypto.KeyPairGenerator;
import org.mozilla.jss.crypto.KeyWrapAlgorithm;
import org.mozilla.jss.crypto.KeyWrapper;
import org.mozilla.jss.crypto.PQGParamGenException;
import org.mozilla.jss.crypto.PQGParams;
import org.mozilla.jss.crypto.SignatureAlgorithm;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.util.IncorrectPasswordException;
import org.mozilla.jss.util.NotImplementedException;
import org.mozilla.jss.util.NullPasswordCallback;
import org.mozilla.jss.util.Password;
import org.mozilla.jss.util.PasswordCallback;
import org.mozilla.jss.util.PasswordCallbackInfo;

/**
 * A PKCS #11 token.  Currently, these can only be obtained from the
 * CryptoManager class.
 *
 * @author nicolson
 * @version $Revision$ $Date$
 * @see org.mozilla.jss.CryptoManager
 */
public final class PK11Token implements CryptoToken {

    protected TokenProxy tokenProxy;
    protected PK11Store cryptoStore;

    protected boolean mIsInternalCryptoToken;
    protected boolean mIsInternalKeyStorageToken;

    ////////////////////////////////////////////////////
    //  exceptions
    ////////////////////////////////////////////////////
    /**
     * Thrown if the operation requires that the token be logged in, and it
     * isn't.
     */
    public static class NotInitializedException
            extends IncorrectPasswordException
    {
        private static final long serialVersionUID = 1L;
        public NotInitializedException() {}
        public NotInitializedException(String mesg) {super(mesg);}
    }

    ////////////////////////////////////////////////////
    //  public routines
    ////////////////////////////////////////////////////
    @Override
    public org.mozilla.jss.crypto.Signature
    getSignatureContext(SignatureAlgorithm algorithm)
            throws NoSuchAlgorithmException, TokenException
    {
        assert(algorithm!=null);
        return Tunnel.constructSignature( algorithm,
                new PK11Signature(this, algorithm) );
    }

    @Override
    public JSSMessageDigest
    getDigestContext(DigestAlgorithm algorithm)
            throws NoSuchAlgorithmException,
            java.security.DigestException
    {
        if( ! doesAlgorithm(algorithm) ) {
            throw new NoSuchAlgorithmException();
        }

        return new PK11MessageDigest(this, algorithm);
    }

    @Override
    public Cipher
    getCipherContext(EncryptionAlgorithm algorithm)
            throws NoSuchAlgorithmException, TokenException
    {
        if( ! doesAlgorithm(algorithm) ) {
            throw new NoSuchAlgorithmException(
                algorithm+" is not supported by this token");
        }
        return new PK11Cipher(this, algorithm);
    }

    @Override
    public KeyGenerator
    getKeyGenerator(KeyGenAlgorithm algorithm)
        throws NoSuchAlgorithmException, TokenException
    {
        return new PK11KeyGenerator(this, algorithm);
    }

    /**
     * Allows a SymmetricKey to be cloned on a different token.
     *
     * @exception SymmetricKey.NotExtractableException If the key material
     *      cannot be extracted from the current token.
     * @exception InvalidKeyException If the owning token cannot process
     *      the key to be cloned.
     */
    @Override
    public SymmetricKey cloneKey(SymmetricKey key)
        throws SymmetricKey.NotExtractableException,
            InvalidKeyException, TokenException
    {
        return PK11KeyGenerator.clone(key, this);
    }

    @Override
    public PK11SymmetricKeyDeriver getSymmetricKeyDeriver()
    {
         return new PK11SymmetricKeyDeriver(this);
    }

    @Override
    public KeyWrapper
    getKeyWrapper(KeyWrapAlgorithm algorithm)
        throws NoSuchAlgorithmException, TokenException
    {

        return new PK11KeyWrapper(this, algorithm);
    }

    public java.security.SecureRandom
    getRandomGenerator()
            throws NotImplementedException, TokenException
    {
        throw new NotImplementedException();
    }

    @Override
    public org.mozilla.jss.crypto.KeyPairGenerator
    getKeyPairGenerator(KeyPairAlgorithm algorithm)
            throws NoSuchAlgorithmException, TokenException
    {
        assert(algorithm!=null);
        return new KeyPairGenerator(algorithm,
                new PK11KeyPairGenerator(this, algorithm));
    }

    @Override
    public native boolean isLoggedIn() throws TokenException;

    @Override
    public native boolean needsLogin() throws TokenException;


    /**
     * Log into the token. If you are already logged in, this method has
     * no effect, even if the PIN is wrong.
     *
     * @param callback A callback to use to obtain the password, or a
     *      Password object.
     * @exception NotInitializedException The token has not yet been
     *  initialized.
     * @exception IncorrectPasswordException The specified password
     *      was incorrect.
     */
    @Override
    public void login(PasswordCallback callback)
        throws IncorrectPasswordException,
			TokenException
	{
        if(callback == null) {
            callback = new NullPasswordCallback();
        }
        nativeLogin(callback);
	}

	protected native void nativeLogin(PasswordCallback callback)
        throws IncorrectPasswordException,
        TokenException;

    /**
     * @return true if the token is writable, false if it is read-only.
     *  Writable tokens can have their keys generated on the internal token
     *  and then moved out.
     */
    public native boolean isWritable();

    /**
     * Determines if the given token is present on the system.
     * This would return false, for example, for a smart card reader
     * that didn't have a card inserted.
     */
    @Override
    public native boolean isPresent();

    /**
     * Log out of the token.
     *
     * @exception TokenException If you are already logged in, or an
     *  unspecified error occurs.
     */
    @Override
    public native void logout() throws TokenException;

    @Override
    public native int getLoginMode() throws TokenException;

    @Override
    public native void setLoginMode(int mode) throws TokenException;

    @Override
    public native int getLoginTimeoutMinutes() throws TokenException;

    @Override
    public native void setLoginTimeoutMinutes(int timeoutMinutes)
            throws TokenException;

    /**
     * Determines whether this is a removable token. For example, a smart card
     * is removable, while the Netscape internal module and a hardware
     * accelerator card are not removable.
     * @return true if the token is removable, false otherwise.
     */
    //public native boolean isRemovable();

    /**
     * Initialize PIN.  This sets the user's new PIN, using the current
     * security officer PIN for authentication.
     *
     * @param ssopwcb The security officer's current password callback.
     * @param userpwcb The user's new password callback.
     * @exception IncorrectPasswordException If the security officer PIN is
     *  incorrect.
     * @exception AlreadyInitializedException If the password hasn't already
     *  been set.
     * @exception TokenException If the PIN was already initialized,
     *  or there was an unspecified error in the token.
     */
    @Override
    public void initPassword(PasswordCallback ssopwcb,
		PasswordCallback userpwcb)
        throws IncorrectPasswordException, AlreadyInitializedException,
		TokenException
	{
		byte[] ssopwArray = null;
		byte[] userpwArray = null;
        Password ssopw=null;
        Password userpw=null;
		PasswordCallbackInfo pwcb = makePWCBInfo();

        if(ssopwcb==null) {
            ssopwcb = new NullPasswordCallback();
        }
        if(userpwcb==null) {
            userpwcb = new NullPasswordCallback();
        }

		try {

			// Make sure the password hasn't already been set, doing special
			// checks for the internal module
			if(!PWInitable()) {
				throw new AlreadyInitializedException();
			}

			// Verify the SSO Password, except on internal module
            if( isInternalKeyStorageToken() ) {
                ssopwArray = new byte[] {0};
            } else {
			    ssopw = ssopwcb.getPasswordFirstAttempt(pwcb);
			    ssopwArray = Tunnel.getPasswordByteCopy(ssopw);
			    while( ! SSOPasswordIsCorrect(ssopwArray) ) {
				    Password.wipeBytes(ssopwArray);
                    ssopw.clear();
				    ssopw = ssopwcb.getPasswordAgain(pwcb);
				    ssopwArray = Tunnel.getPasswordByteCopy(ssopw);
			    }
            }

			// Now change the PIN
			userpw = userpwcb.getPasswordFirstAttempt(pwcb);
			userpwArray = Tunnel.getPasswordByteCopy(userpw);
			initPassword(ssopwArray, userpwArray);

		} catch (PasswordCallback.GiveUpException e) {
			throw new IncorrectPasswordException(e.toString());
		} finally {
			// zero-out the arrays
			if(ssopwArray != null) {
				Password.wipeBytes(ssopwArray);
			}
            if(ssopw != null) {
                ssopw.clear();
            }
			if(userpwArray != null) {
				Password.wipeBytes(userpwArray);
			}
            if(userpw != null) {
                userpw.clear();
            }
		}
	}

	/**
	 * Make sure the PIN can be initialized.  This is mainly to check the
	 * internal module.
	 */
	protected native boolean PWInitable() throws TokenException;

	protected native boolean SSOPasswordIsCorrect(byte[] ssopw)
		throws TokenException, AlreadyInitializedException;

	protected native void initPassword(byte[] ssopw, byte[] userpw)
		throws IncorrectPasswordException, AlreadyInitializedException,
		TokenException;

	/**
	 * Determine whether the token has been initialized yet.
	 */
	@Override
    public native boolean
	passwordIsInitialized() throws TokenException;

    /**
     * Change password.  This changes the user's PIN after it has already
     * been initialized.
     *
     * @param oldPINcb The user's old PIN callback.
     * @param newPINcb The new PIN callback.
     * @exception IncorrectPasswordException If the old PIN is incorrect.
     * @exception TokenException If some other error occurs on the token.
     *
     */
    @Override
    public void changePassword(PasswordCallback oldPINcb,
			PasswordCallback newPINcb)
        throws IncorrectPasswordException, TokenException
	{
		byte[] oldPW = null;
		byte[] newPW = null;
        Password oldPIN=null;
        Password newPIN=null;
		PasswordCallbackInfo pwcb = makePWCBInfo();

        if(oldPINcb==null) {
            oldPINcb = new NullPasswordCallback();
        }
        if(newPINcb==null) {
            newPINcb = new NullPasswordCallback();
        }

		try {

			// Verify the old password
			oldPIN = oldPINcb.getPasswordFirstAttempt(pwcb);
			oldPW = Tunnel.getPasswordByteCopy(oldPIN);
			if( ! userPasswordIsCorrect(oldPW) ) {
				do {
					Password.wipeBytes(oldPW);
                    oldPIN.clear();
					oldPIN = oldPINcb.getPasswordAgain(pwcb);
					oldPW = Tunnel.getPasswordByteCopy(oldPIN);
				} while( ! userPasswordIsCorrect(oldPW) );
			}

			// Now change the PIN
			newPIN = newPINcb.getPasswordFirstAttempt(pwcb);
			newPW = Tunnel.getPasswordByteCopy(newPIN);
			changePassword(oldPW, newPW);

		} catch (PasswordCallback.GiveUpException e) {
			throw new IncorrectPasswordException(e.toString());
		} finally {
			if(oldPW != null) {
				Password.wipeBytes(oldPW);
			}
            if(oldPIN != null) {
                oldPIN.clear();
            }
			if(newPW != null) {
				Password.wipeBytes(newPW);
			}
            if(newPIN != null) {
                newPIN.clear();
            }
		}
	}

	protected PasswordCallbackInfo makePWCBInfo() {
		return new TokenCallbackInfo(getName());
	}

	/**
	 * Check the given password, return true if it's right, false if it's
	 * wrong.
	 */
	protected native boolean userPasswordIsCorrect(byte[] pw)
		throws TokenException;

	/**
	 * Change the password on the token from the old one to the new one.
	 */
    protected native void changePassword(byte[] oldPIN, byte[] newPIN)
        throws IncorrectPasswordException, TokenException;

    @Override
    public native String getName();

	public java.security.Provider
	getProvider() {
	    throw new RuntimeException("PK11Token.getProvider() is not yet implemented");
	}

	@Override
    public CryptoStore
	getCryptoStore() {
		return cryptoStore;
	}

	/**
	 * Determines whether this token is capable of performing the given
	 * PKCS #11 mechanism.
	 */
/*
	public boolean doesMechanism(Mechanism mech) {
        return doesMechanismNative(mech.getValue());
    }
*/

    /**
     * Deep-comparison operator.
     *
     * @return true if these tokens point to the same underlying native token.
     *  false otherwise, or if <code>compare</code> is null.
     */
    @Override
    public boolean equals(Object obj) {
        if(obj==null) {
            return false;
        } else {
            if( ! (obj instanceof PK11Token) ) {
                return false;
            }
            return tokenProxy.equals(((PK11Token)obj).tokenProxy);
        }
    }

    /**
     * HashCode from underline token.
     *
     * Two token are equals if they have the same underline native token so
     * they should return the same hash code
     * @return The hash code of the underlying token.
     */
    @Override
    public int hashCode() {
        return tokenProxy.hashCode();
    }

    //protected native boolean doesMechanismNative(int mech);

	/**
	 * Determines whether this token is capable of performing the given
	 * algorithm.
	 */
    @Override
    public native boolean doesAlgorithm(Algorithm alg);

	/**
	 * Generates a PKCS#10 certificate request including Begin/End brackets
	 * @param subject subject dn of the certificate
	 * @param keysize size of the key
	 * @param keyType "rsa" or "dsa"
	 * @param prime The DSA prime parameter
	 * @param subPrime The DSA sub-prime parameter
	 * @param base The DSA base parameter
	 * @return String that represents a PKCS#10 b64 encoded blob with
	 * begin/end brackets
	 */
	@Override
        public String generateCertRequest(String subject, int keysize,
                String keyType,
                byte[] prime, byte[] subPrime, byte[] base)
                throws TokenException, InvalidParameterException, PQGParamGenException {
            String pk10String;
            byte[] p = prime;
            byte[] q = subPrime;
            byte[] g = base;

            if (keyType.equalsIgnoreCase("dsa")) {
                if ((p == null) && (q == null) && (g == null)) {
                    PQGParams pqg = PQGParams.generate(keysize);
                    p = PQGParams.BigIntegerToUnsignedByteArray(pqg.getP());
                    q = PQGParams.BigIntegerToUnsignedByteArray(pqg.getQ());
                    g = PQGParams.BigIntegerToUnsignedByteArray(pqg.getG());
                 } else if ((p == null) || (q == null) || (g == null)) {
                    throw new InvalidParameterException("need all P, Q, and G");
                }
            }
            pk10String = generatePK10(subject, keysize, keyType, p,
                    q, g);
            return Cert.REQUEST_HEADER + "\n" + pk10String + "\n" + Cert.REQUEST_FOOTER;
        }

	protected native String generatePK10(String subject, int keysize,
											 String keyType,
											 byte[] P, byte[] Q,
											 byte[] G)
		throws TokenException, InvalidParameterException;

    ////////////////////////////////////////////////////
    // construction and finalization
    ////////////////////////////////////////////////////

    /*
     * Default constructor should never be called.
     */
    protected PK11Token() {
        assert(false);
    }

    /**
     * Creates a new PK11Token.  Should only be called from PK11Token's
     * native code.
     * @param pointer A byte array containing a pointer to a PKCS #11 slot.
     */
    protected PK11Token(byte[] pointer, boolean internal, boolean keyStorage) {
        assert(pointer!=null);
        tokenProxy = new TokenProxy(pointer);
        mIsInternalCryptoToken = internal;
        mIsInternalKeyStorageToken = keyStorage;
        cryptoStore = new PK11Store(tokenProxy);
    }

/*
	protected PK11Token(TokenProxy proxy) {
        assert(proxy!=null);
		this.tokenProxy = proxy;
	}
*/

    public TokenProxy getProxy() {
        return tokenProxy;
    }

    /**
     * @return true if this is the internal token used for bulk crypto.
     */
    public boolean isInternalCryptoToken() {
        return mIsInternalCryptoToken;
    }

    /**
     * @return true if this is the internal key storage token.
     */
    public boolean isInternalKeyStorageToken() {
        return mIsInternalKeyStorageToken;
    }

    @Override
    public native void importPublicKey(
            PublicKey pubKey,
            boolean permanent)
            throws TokenException;
}

/**
 * This class just hard-wires the type to be TOKEN so we don't have to mess
 * with Java constants in native code.
 */
class TokenCallbackInfo extends PasswordCallbackInfo {
	public TokenCallbackInfo(String name) {
		super(name, TOKEN);
	}
}
