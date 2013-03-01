/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.crypto;

import java.security.*;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

/**
 * Generates RSA and DSA key pairs.  Each CryptoToken provides a
 * KeyPairGenerator, which can be used to generate key pairs on that token.
 * A given token may not support all algorithms, and some tokens may not
 * support any key pair generation. If a token does not support key pair
 * generation, the Netscape internal token may do it instead. Call
 * <code>keygenOnInternalToken</code> to find out if this is happening.
 *
 * @see org.mozilla.jss.crypto.CryptoToken#getKeyPairGenerator
 * @deprecated Use the JCA interface instead ({@link java.security.KeyPairGenerator})
 */
public class KeyPairGenerator {

    /**
     * Creates a new key pair generator.  KeyPairGenerators should
     * be obtained by calling <code>CryptoToken.getKeyPairGenerator</code>
     * instead of calling this constructor.
     *
     * @param algorithm The type of keys that the generator will be
     *      used to generate.
     * @param engine The engine object that provides the implementation for
     *      the class.
     */
	public KeyPairGenerator(KeyPairAlgorithm algorithm,
							KeyPairGeneratorSpi engine) {
		this.algorithm = algorithm;
		this.engine = engine;
	}

    /**
     * Generates a new key pair.
     *
     * @return A new key pair. The keys reside on the CryptoToken that 
     *      provided this <code>KeyPairGenerator</code>.
     * @exception TokenException If an error occurs on the CryptoToken
     *      in the process of generating the key pair.
     */
	public java.security.KeyPair
	genKeyPair() throws TokenException {
		return engine.generateKeyPair();
	}
    /**
     * @return The type of key that this generator generates.
     */
	public KeyPairAlgorithm getAlgorithm() {
		return algorithm;
	}

    /**
     * Initializes the generator with algorithm-specific parameters.
     *  The <tt>SecureRandom</tt> parameters is ignored.
     *
     * @param params Algorithm-specific parameters for the key pair generation.
     * @param random <b>This parameter is ignored.</b> NSS does not accept
     *      an external source of random numbers.
     * @exception InvalidAlgorithmParameterException If the parameters are
     *      inappropriate for the type of key pair that is being generated,
     *      or they are not supported by this generator.
     * @see org.mozilla.jss.crypto.RSAParameterSpec
     * @see java.security.spec.DSAParameterSpec
     */
	public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException
    {
		engine.initialize(params, random);
	}

    /**
     * Initializes the generator with algorithm-specific parameters.
     *
     * @param params Algorithm-specific parameters for the key pair generation.
     * @exception InvalidAlgorithmParameterException If the parameters are
     *      inappropriate for the type of key pair that is being generated,
     *      or they are not supported by this generator.
     * @see org.mozilla.jss.crypto.RSAParameterSpec
     * @see java.security.spec.DSAParameterSpec
     */
	public void initialize(AlgorithmParameterSpec params)
		throws InvalidAlgorithmParameterException
	{
		engine.initialize(params, null);
	}

    /**
     * Initializes the generator with the strength of the keys.
     *      The <tt>SecureRandom</tt> parameter is ignored.
     *
     * @param strength The strength of the keys that will be generated.
     *      Usually this is the length of the key in bits.
     * @param random <b>This parameter is ignored.</b> NSS does not accept
     *      an external source of random numbers.
     */
	public void initialize(int strength, SecureRandom random) {
		engine.initialize(strength, random);
	}

    /**
     * Initializes the generator with the strength of the keys.
     *
     * @param strength The strength of the keys that will be generated.
     *      Usually this is the length of the key in bits.
     */
	public void initialize(int strength) {
		engine.initialize(strength, null);
	}

    /**
     * @return true if the keypair generation will take place on the 
     *      internal token rather than the current token.  This will
     *      happen if the token does not support keypair generation
     *      but does support this algorithm and is writable.  In this
     *      case the keypair will be generated on the Netscape internal
     *      token and then moved to this token.
     */
    public boolean keygenOnInternalToken() {
        return engine.keygenOnInternalToken();
    }

    /**
     * Tells the generator to generate temporary or permanent keypairs.
     * Temporary keys are not written permanently to the token.  They
     * are destroyed by the garbage collector.  If this method is not
     * called, the default is permanent keypairs.
     * @param temp
     */
    public void temporaryPairs(boolean temp) {
        engine.temporaryPairs(temp);
    }

    /**
     * Tells the generator to generate sensitive or insensitive keypairs.
     * Certain attributes of a sensitive key cannot be revealed in
     * plaintext outside the token.  If this method is not called, the
     * default depends on the temporaryPairs mode for backward
     * compatibility.  The default is sensitive keypairs if the
     * temporaryPairs mode is false, or insensitive keypairs if the
     * temporaryPairs mode is true.
     * @param sensitive
     */
    public void sensitivePairs(boolean sensitive) {
        engine.sensitivePairs(sensitive);
    }

    /**
     * Tells the generator to generate extractable or unextractable
     * keypairs.  Extractable keys can be extracted from the token after
     * wrapping.  If this method is not called, the default is token
     * dependent.
     * @param extractable 
     */
    public void extractablePairs(boolean extractable) {
        engine.extractablePairs(extractable);
    }

    public void setKeyPairUsages(KeyPairGeneratorSpi.Usage[] usages,
                                 KeyPairGeneratorSpi.Usage[] usages_mask) {
        engine.setKeyPairUsages(usages,usages_mask);
    }

	protected KeyPairAlgorithm algorithm;
	protected KeyPairGeneratorSpi engine;
}
