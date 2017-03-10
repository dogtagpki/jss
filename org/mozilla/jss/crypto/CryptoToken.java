/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.crypto;

import org.mozilla.jss.util.*;
import java.security.*;

/**
 * A CryptoToken performs cryptographic operations and stores
 * cryptographic items, such as keys and certs.  It corresponds to a
 * Cryptographic Service Provider (CSP) in CDSA, and to a PKCS #11 token.
 * <p>Instances of CryptoToken are obtained from CryptoManager.
 * @see org.mozilla.jss.CryptoManager
 */
public interface CryptoToken {

//
// SERVICES
//
    /**
     * Creates a Signature object, which can perform signing and signature
     * verification. Signing and verification cryptographic operations will
     * take place on this token. The signing key must be located on this
     * token.
     *
     * @param algorithm The algorithm used for the signing/verification.
     * @exception java.security.NoSuchAlgorithmException If the given
     *      algorithm is not supported by this provider.
     */
    public abstract org.mozilla.jss.crypto.Signature
    getSignatureContext(SignatureAlgorithm algorithm)
        throws java.security.NoSuchAlgorithmException, TokenException;

    /**
     * Creates a Digest object.  Digesting cryptographic operations will
     * take place on this token.
     *
     * @param algorithm The algorithm used for digesting.
     * @exception java.security.NoSuchAlgorithmException If this provider
     *  does not support the given algorithm.
     */
    public abstract JSSMessageDigest
    getDigestContext(DigestAlgorithm algorithm)
        throws java.security.NoSuchAlgorithmException, DigestException;

    // !!! MAC ???

    /**
     * Creates a Cipher object, which can be used for encryption and
     * decryption. Cryptographic operations will take place on this token.
     * The keys used in the operations must be located on this token.
     *
     * @param algorithm The algorithm used for encryption/decryption.
     * @exception java.security.NoSuchAlgorithmException If this provider
     *      does not support the given algorithm.
     */
    public abstract Cipher
    getCipherContext(EncryptionAlgorithm algorithm)
        throws java.security.NoSuchAlgorithmException, TokenException;

    public abstract SymmetricKeyDeriver getSymmetricKeyDeriver()
        throws TokenException;

    public abstract KeyWrapper
    getKeyWrapper(KeyWrapAlgorithm algorithm)
        throws java.security.NoSuchAlgorithmException, TokenException;

    /**
     * Returns a Random Number Generator implemented on this token.
     *
     * @exception org.mozilla.jss.crypto.ServiceNotProvidedException If this token
     *      does not perform random number generation
     */
    /*
    public abstract SecureRandom getRandomGenerator()
        throws NotImplementedException, TokenException;
    */

    // !!! Derive Keys ???

    /**
     * Creates a KeyGenerator object, which can be used to generate
     * symmetric encryption keys.  Any keys generated with this KeyGenerator
     * will be generated on this token.
     *
     * @param algorithm The algorithm that the keys will be used with.
     * @exception java.security.NoSuchAlgorithmException If this token does not
     *      support the given algorithm.
     */
    public abstract KeyGenerator
    getKeyGenerator(KeyGenAlgorithm algorithm)
        throws java.security.NoSuchAlgorithmException, TokenException;

    /**
     * Clones a SymmetricKey from a different token onto this token.
     *
     * @exception SymmetricKey.NotExtractableException If the key material
     *      cannot be extracted from the current token.
     * @exception InvalidKeyException If the owning token cannot process
     *      the key to be cloned.
     */
    public SymmetricKey cloneKey(SymmetricKey key)
        throws SymmetricKey.NotExtractableException,
            InvalidKeyException, TokenException;

    /**
     * Creates a KeyPairGenerator object, which can be used to generate
     * key pairs. Any keypairs generated with this generator will be generated
     * on this token.
     *
     * @param algorithm The algorithm that the keys will be used with (RSA,
     *      DSA, EC, etc.)
     * @exception java.security.NoSuchAlgorithmException If this token does
     *      not support the given algorithm.
     */
    public abstract KeyPairGenerator
    getKeyPairGenerator(KeyPairAlgorithm algorithm)
        throws java.security.NoSuchAlgorithmException, TokenException;

	/**
	 * Generates a b64 encoded PKCS10 blob used for making cert
	 *	 request.  Begin/End brackets included.
	 * @param subject subject dn of the certificate
	 * @param keysize size of the key
	 * @param keyType "rsa" or "dsa"
     * @param P The DSA prime parameter
     * @param Q The DSA sub-prime parameter
     * @param G The DSA base parameter
	 * @return base64 encoded pkcs10 certificate request with
	 *	 Begin/end brackets
	 */
	public abstract String generateCertRequest(String subject, int
											   keysize,
											   String keyType,
											   byte[] P, byte[] Q,
											   byte[] G)
		throws TokenException, InvalidParameterException,
												   PQGParamGenException;

    /**
     * Determines whether this token supports the given algorithm.
     *
     * @param alg A JSS algorithm.  Note that for Signature, a token may
     *      fail to support a specific SignatureAlgorithm (such as
     *      RSASignatureWithMD5Digest) even though it does support the
     *      generic algorithm (RSASignature). In this case, the signature
     *      operation will be performed on that token, but the digest
     *      operation will be performed on the internal token.
     * @return true if the token supports the algorithm.
     */
    public boolean doesAlgorithm(Algorithm alg);

    /**
     * Login to the token. If a token is logged in, it will not trigger
     * password callbacks.
     *
     * @param pwcb The password callback for this token.
     * @exception IncorrectPasswordException If the supplied password is
     *  incorrect.
     * @see #setLoginMode
     * @see org.mozilla.jss.CryptoManager#setPasswordCallback
     */
    public abstract void login(PasswordCallback pwcb)
        throws IncorrectPasswordException, TokenException;

    /**
     * Logout of the token.
     *
     */
    public abstract void logout() throws TokenException;

    /**
     * Login once, never need to re-enter the password until you log out.
     */
    public static final int ONE_TIME=0;
    /**
     * Need to re-login after a period of time.
     * @see org.mozilla.jss.crypto.CryptoToken#setLoginTimeoutMinutes
     */
    public static final int TIMEOUT=1;
    /**
     * Need to provide a password before each crypto operation.
     */
    public static final int EVERY_TIME=2;

    /**
     * Returns the login mode of this token: ONE_TIME, TIMEOUT, or
     * EVERY_TIME.  The default is ONE_TIME.
     * @see #getLoginTimeoutMinutes
     * @exception TokenException If an error occurs on the token.
     */
    public abstract int getLoginMode() throws TokenException;

    /**
     * Sets the login mode of this token.
     *
     * @param mode ONE_TIME, TIMEOUT, or EVERY_TIME
     * @exception TokenException If this mode is not supported by this token,
     *  or an error occurs on the token.
     * @see #login
     * @see #setLoginTimeoutMinutes
     */
    public abstract void setLoginMode(int mode) throws TokenException;

    /**
     * Returns the login timeout period.  The timeout is only used if the
     * login mode is TIMEOUT.
     *
     * @see #getLoginMode
     * @exception TokenException If an error occurs on the token.
     */
    public abstract int getLoginTimeoutMinutes() throws TokenException;

    /**
     * Sets the timeout period for logging in. This will only be used
     * if the login mode is TIMEOUT.
     *
     * @exception TokenException If timeouts are not supported by this
     *      token, or an error occurs on the token.
     * @see #setLoginMode
     */
    public abstract void setLoginTimeoutMinutes(int timeoutMinutes)
        throws TokenException;

    /**
     * Find out if the token is currently logged in.
     *
     * @see #login
     * @see #logout
     */
    public boolean isLoggedIn() throws TokenException;

    /**
     * returns true if this token needs to be logged into before
     * it can be used.
     *
     * @see #login
     * @see #logout
     */
    public boolean needsLogin() throws TokenException;


	/**
	 * Initialize the password of this token.
	 *
	 * @param securityOfficerPW A callback to obtain the password of the
	 * 		SecurityOfficer.  Pass in a NullPasswordCallback if there is
	 * 		no security officer password. Must not be null.
	 * @param userPW A callback to obtain the new password for this token.
	 *		Must not be null.
	 * @exception IncorrectPasswordException If the supplied security officer
	 *		password is incorrect.
	 * @exception AlreadyInitializedException If the token only allows one
	 *		password initialization, and it has already occurred.
     * @exception TokenException If an error occurs on the token.
	 */
	public abstract void
	initPassword(PasswordCallback securityOfficerPW, PasswordCallback userPW)
		throws IncorrectPasswordException, AlreadyInitializedException,
		TokenException;

	/**
	 * Determine whether the password has been initialized yet.  Some tokens
	 * (such as the Netscape Internal Key Token) don't allow initializing
	 * the PIN more than once.
     *
     * @exception TokenException If an error occurs on the token.
	 */
	public abstract boolean
	passwordIsInitialized() throws TokenException;

    /**
     * Change the password of this token.
     *
     * @exception IncorrectPasswordException If the supplied old password is
     *      incorrect.
     * @param oldpw A callback (which could be just a Password) to retrieve
     *      the current password.
     * @param newpw A callback (which could be just a Password) to retrieve
     *      the new password.
     */
    public abstract void
    changePassword(PasswordCallback oldpw, PasswordCallback newpw)
        throws IncorrectPasswordException, TokenException;

    /**
     * Obtain the nickname, or label, of this token.
     *
     * @exception TokenException If an error occurs on the token.
     */
    public abstract String getName() throws TokenException;

    /**
     * Get the CryptoStore interface to this token's objects.
     */
    public abstract CryptoStore getCryptoStore();

    /**
     * Deep comparison operation. Use this, rather than ==, to determine
     * whether two CryptoTokens are the same.
     */
    public boolean equals(Object object);

    /**
     * Determines whether this token is currently present.
     * This could return false if the token is a smart card that was
     * removed from its slot.
     */
    public boolean isPresent();
}
