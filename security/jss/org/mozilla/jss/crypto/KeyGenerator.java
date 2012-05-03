/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.crypto;

import java.security.spec.AlgorithmParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.io.CharConversionException;

/**
 * Generates symmetric keys for encryption and decryption.
 * @deprecated Use the JCA interface instead ({@link javax.crypto.KeyGenerator})
 */
public interface KeyGenerator {

    /**
     * @param strength Key size in bits. Must be evenly divisible by 8.
     */
    public void initialize(int strength)
        throws InvalidAlgorithmParameterException;

    public void initialize(AlgorithmParameterSpec parameters)
        throws InvalidAlgorithmParameterException;

    /**
     * @param usages The operations the key will be used for after it is
     *   generated. You have to specify these so that the key can be properly
     *   marked with the operations it supports. Some PKCS #11 tokens require
     *   that a key be marked for an operation before it can perform that
     *   operation.  The default is SymmetricKey.Usage.SIGN and
     *   SymmetricKey.Usage.ENCRYPT.
     */
    public void setKeyUsages(SymmetricKey.Usage[] usages);

    /**
     * Tells the generator to generate temporary or permanent keys.
     * Temporary keys are not written permanently to the token.  They
     * are destroyed by the garbage collector.  If this method is not
     * called, the default is temporary keys.
     */
    public void temporaryKeys(boolean temp);

    /**
     * Tells the generator to generate sensitive or insensitive keys.
     * Certain attributes of a sensitive key cannot be revealed in
     * plaintext outside the token.  If this method is not called, the
     * default is token dependent.
     */
    public void sensitiveKeys(boolean sensitive);

    /**
     * Generates a symmetric key.
     */
    public SymmetricKey generate()
        throws IllegalStateException, TokenException, CharConversionException;

    /**
     * Generates an Initialization Vector using a PBE algorithm.
     * In order to call this method, the algorithm must be a PBE algorithm,
     * and the KeyGenerator must have been initialized with an instance
     * of <code>PBEKeyGenParams</code>.
     *
     * @return The initialization vector derived from the password and salt
     *      using the PBE algorithm.
     * @exception IllegalStateException If the algorithm is not a PBE
     *      algorithm, or the KeyGenerator has not been initialized with
     *      an instance of <code>PBEKeyGenParams</code>.
     * @exception TokenException If an error occurs on the CryptoToken while
     *      generating the IV.
     */
    public byte[] generatePBE_IV()
        throws IllegalStateException, TokenException, CharConversionException;

    /**
     * Allows a SymmetricKey to be cloned on a different token.
     *
     * @exception SymmetricKey.NotExtractableException If the key material
     *      cannot be extracted from the current token.
     * @exception InvalidKeyException If the owning token cannot process
     *      the key to be cloned.
     */
    public SymmetricKey clone(SymmetricKey key)
        throws SymmetricKey.NotExtractableException,
            InvalidKeyException, TokenException;

    /**
     * An interface for converting a password of Java characters into an array
     * of bytes. This conversion must be performed to provide a byte array
     * to the low-level crypto engine.  The default conversion is UTF8.
     * Null-termination is not necessary, and indeed is usually incorrect,
     * since the password is passed to the crypto engine as a byte array, not
     * a C string.
     */
    public static interface CharToByteConverter {

        /**
         * Converts a password of Java characters into a password of
         * bytes, using some encoding scheme.  The input char array must
         * not be modified.
         */
        public byte[] convert(char[] chars) throws CharConversionException;
    }

    /**
     * Sets the character to byte converter for passwords. The default
     * conversion is UTF8 with no null termination.
     */
    public void setCharToByteConverter(CharToByteConverter charToByte);

}
