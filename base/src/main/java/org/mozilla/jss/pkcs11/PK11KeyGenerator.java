/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkcs11;

import java.io.CharConversionException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.spec.AlgorithmParameterSpec;

import org.mozilla.jss.crypto.EncryptionAlgorithm;
import org.mozilla.jss.crypto.HMACAlgorithm;
import org.mozilla.jss.crypto.KBKDFParameterSpec;
import org.mozilla.jss.crypto.KeyGenAlgorithm;
import org.mozilla.jss.crypto.KeyGenerator;
import org.mozilla.jss.crypto.PBEKeyGenParams;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.util.NativeProxy;
import org.mozilla.jss.util.Password;
import org.mozilla.jss.util.UTF8Converter;

public final class PK11KeyGenerator implements KeyGenerator {

    // The token this key will be generated on.
    private PK11Token token;

    // The algorithm to use to generate the key
    private KeyGenAlgorithm algorithm;

    // The strength of the key to be generated in bits.  A value of 0 means
    // that the strength has not been set.  This is OK for most algorithms.
    private int strength=0;

    // The parameters for this algorithm. May be null for some algorithms.
    private AlgorithmParameterSpec parameters;

    // The crypto operations the key will support.  It is the logical OR
    // of the opFlag constants, each specifying a supported operation.
    private long opFlags = PKCS11Constants.CKF_SIGN | PKCS11Constants.CKF_ENCRYPT;

    // Whether the key will be temporary or permanent
    private boolean temporaryKeyMode = true;

    // Whether the key will be sensitive or insensitive
    //  1: sensitive
    //  0: insensitive
    // -1: unspecified (token dependent)
    private int sensitiveKeyMode = -1;

    // Used to convert Java Password into a byte[].
    private KeyGenerator.CharToByteConverter charToByte;

    private PK11KeyGenerator() { }

    // package private constructor
    PK11KeyGenerator(PK11Token token, KeyGenAlgorithm algorithm) {
        if( token==null || algorithm==null ) {
            throw new NullPointerException();
        }
        this.token = token;
        this.algorithm = algorithm;
        charToByte = new KeyGenerator.CharToByteConverter() {
            @Override
            public byte[] convert(char[] chars) throws CharConversionException {
                return UTF8Converter.UnicodeToUTF8(chars);
            }
        };
    }


    /**
     * Sets the character to byte converter for passwords. The default
     * conversion is UTF8 with no null termination.
     */
    @Override
    public void setCharToByteConverter(
                    KeyGenerator.CharToByteConverter charToByte)
    {
        if( charToByte==null ) {
            throw new IllegalArgumentException("CharToByteConverter is null");
        }
        this.charToByte = charToByte;
    }

    /**
     * @param strength Key size in bits. Must be evenly divisible by 8.
     */
    @Override
    public void initialize(int strength)
        throws InvalidAlgorithmParameterException
    {
        // if this algorithm only accepts PBE key gen params, it can't
        // use a strength
        Class<?>[] paramClasses = algorithm.getParameterClasses();
        if( paramClasses.length == 1 &&
                paramClasses[0].equals(PBEKeyGenParams.class) )
        {
            throw new InvalidAlgorithmParameterException("PBE keygen "+
                "algorithms require PBEKeyGenParams ");
        }

        // validate the strength for our algorithm
        if( ! algorithm.isValidStrength(strength) ) {
            throw new InvalidAlgorithmParameterException(strength+
                " is not a valid strength for "+algorithm);
        }

        if( strength % 8 != 0 ) {
            throw new InvalidAlgorithmParameterException(
                "Key strength must be divisible by 8");
        }

        this.strength = strength;
    }

    @Override
    public void initialize(AlgorithmParameterSpec parameters)
        throws InvalidAlgorithmParameterException
    {
        if( ! algorithm.isValidParameterObject(parameters) ) {
            String name = "null";
            if( parameters != null ) {
                name = parameters.getClass().getName();
            }
            throw new InvalidAlgorithmParameterException(
                algorithm + " cannot use a " + name + " parameter");
        }
        this.parameters = parameters;
    }

    @Override
    public void setKeyUsages(SymmetricKey.Usage[] usages)
    {
        this.opFlags = 0;
        for( int i = 0; i < usages.length; i++ ) {
            if( usages[i] != null ) {
                this.opFlags |= usages[i].value();
            }
        }
    }

    public void setKeyUsages(long opFlags) {
        this.opFlags = opFlags;
    }

    @Override
    public void temporaryKeys(boolean temp)
    {
        this.temporaryKeyMode = temp;
    }

    @Override
    public void sensitiveKeys(boolean sensitive)
    {
        this.sensitiveKeyMode = sensitive ? 1 : 0;
    }

    /**
     * Generates the key. This is the public interface, the actual
     * work is done by native methods.
     */
    @Override
    public SymmetricKey generate()
        throws IllegalStateException, TokenException, CharConversionException
    {
        Class<?>[] paramClasses = algorithm.getParameterClasses();
        boolean is_pbe = paramClasses.length == 1 && paramClasses[0].equals(PBEKeyGenParams.class);
        boolean is_kbkdf = paramClasses.length == 1 && parameters instanceof KBKDFParameterSpec;

        if (is_pbe) {
            if(parameters==null || !(parameters instanceof PBEKeyGenParams)) {
                throw new IllegalStateException(
                    "PBE keygen algorithms require PBEKeyGenParams");
            }
            PBEKeyGenParams kgp = (PBEKeyGenParams)parameters;

            byte[] pwbytes=null;
            try {
                pwbytes = charToByte.convert( kgp.getPassword().getChars() );
                return generatePBE(
                    token, algorithm, kgp.getEncryptionAlgorithm(), kgp.getHashAlgorithm(),
                    pwbytes, kgp.getSalt(), kgp.getIterations());
            } finally {
                if( pwbytes!=null ) {
                    Password.wipeBytes(pwbytes);
                }
            }
        } else if (is_kbkdf) {
            KBKDFParameterSpec kps = (KBKDFParameterSpec) parameters;
            SymmetricKey result = null;

            try {
                try {
                    kps.open();

                    long pkcs11_alg = algorithm.getEnum().getValue();
                    result = generateKBKDF(token, kps.prfKey, pkcs11_alg,
                                           kps.mPointer, kps.mPointerSize,
                                           kps.derivedKeyAlgorithm,
                                           kps.keySize,
                                           (int) opFlags,
                                           temporaryKeyMode, sensitiveKeyMode);
                } finally {
                    kps.close();
                }
            } catch (Exception e) {
                throw new RuntimeException(e.getMessage(), e);
            }

            return result;
        } else {
            return generateNormal(
                    token,
                    algorithm,
                    strength,
                    (int) opFlags,
                    temporaryKeyMode,
                    sensitiveKeyMode);
        }
    }

    /**
     * Generates an Initialization Vector using a PBE algorithm.
     * In order to call this method, the algorithm must be a PBE algorithm,
     * and the KeyGenerator must have been initialized with an instance
     * of <code>PBEKeyGenParams</code>.
     *
     * @return The initialization vector derived from the password and salt
     *      using the PBE algorithm.
     */
    @Override
    public byte[] generatePBE_IV()
        throws TokenException, CharConversionException
    {
        Class<?>[] paramClasses = algorithm.getParameterClasses();
        boolean is_pbe = paramClasses.length == 1 && paramClasses[0].equals(PBEKeyGenParams.class);

        if (is_pbe) {
            if(parameters==null || !(parameters instanceof PBEKeyGenParams)) {
                throw new IllegalStateException(
                    "PBE keygen algorithms require PBEKeyGenParams");
            }
            PBEKeyGenParams kgp = (PBEKeyGenParams)parameters;

            byte[] pwbytes=null;
            try {
                pwbytes = charToByte.convert(kgp.getPassword().getChars());
                return generatePBE_IV(algorithm, pwbytes, kgp.getSalt(),
                                    kgp.getIterations() );
            } finally {
                if(pwbytes!=null) {
                    Password.wipeBytes(pwbytes);
                }
            }
        } else {
            throw new IllegalStateException(
                "IV generation can only be performed by PBE algorithms");
        }
    }

    /**
     * A native method to generate an IV using a PBE algorithm.
     * None of the parameters should be NULL.
     */
    private static native byte[]
    generatePBE_IV(KeyGenAlgorithm alg, byte[] password, byte[] salt,
                    int iterations) throws TokenException;

    /**
     * Allows a SymmetricKey to be cloned on a different token.
     *
     * @exception SymmetricKey.NotExtractableException If the key material
     *      cannot be extracted from the current token.
     * @exception InvalidKeyException If the owning token cannot process
     *      the key to be cloned.
     */
    @Override
    public SymmetricKey clone(SymmetricKey key)
        throws SymmetricKey.NotExtractableException,
            InvalidKeyException, TokenException
    {
        return clone(key, token);
    }

    /**
     * Allows a SymmetricKey to be cloned on a different token.
     *
     * @param key The key to clone.
     * @param token The token on which to clone the key.
     * @exception SymmetricKey.NotExtractableException If the key material
     *      cannot be extracted from the current token.
     * @exception InvalidKeyException If the owning token cannot process
     *      the key to be cloned.
     */
    public static SymmetricKey clone(SymmetricKey key, PK11Token token)
        throws SymmetricKey.NotExtractableException, InvalidKeyException,
            TokenException
    {
        if( ! (key instanceof PK11SymKey) ) {
            throw new InvalidKeyException("Key is not a PKCS #11 key");
        }
        return nativeClone(token, key);
    }

    private static native SymmetricKey
    nativeClone(PK11Token token, SymmetricKey toBeCloned)
        throws SymmetricKey.NotExtractableException, TokenException;


    /**
     * A native method to generate a non-PBE key.
     * @param token The token where the key generation happens
     * @param algorithm The algorithm to use
     * @param strength The key size in bits, should be 0 for fixed-length
     *      key algorithms.
     * @param opFlags The crypto operations the key will support
     * @param temporary Whether the key will be temporary or permanent
     */
    private static native SymmetricKey
    generateNormal(PK11Token token, KeyGenAlgorithm algorithm, int strength,
        int opFlags, boolean temporary, int sensitive)
        throws TokenException;

    /**
     * A native method to generate a PBE key. None of the parameters should
     *  be null.
     */
    private static native SymmetricKey
    generatePBE(
        PK11Token token, KeyGenAlgorithm algorithm, EncryptionAlgorithm encAlg,
        HMACAlgorithm hashAlg, byte[] pass, byte[] salt, int iterationCount)
        throws TokenException;

    /**
     * A native method to generate a key using KBKDF. None of the parameters
     * should be null.
     */
    private static native SymmetricKey
    generateKBKDF(PK11Token token, PK11SymKey baseKeyObj, long algorithm,
        NativeProxy pointer, long pointer_size, long derivedKeyAlgorithm,
        int strength, int opFlags, boolean temporary, int sensitive)
        throws TokenException;

}
