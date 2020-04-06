/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkcs11;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.RC2ParameterSpec;

import org.mozilla.jss.crypto.EncryptionAlgorithm;
import org.mozilla.jss.crypto.IVParameterSpec;
import org.mozilla.jss.crypto.IllegalBlockSizeException;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.crypto.TokenException;

public final class PK11Cipher
    extends org.mozilla.jss.crypto.Cipher
    implements java.lang.AutoCloseable
{

    // set once in the constructor
    private PK11Token token;

    // set once in the constructor
    private EncryptionAlgorithm algorithm;

    // set with initXXX()
    private AlgorithmParameterSpec parameters=null;

    // set with initXXX()
    private SymmetricKey key=null;

    // set with initXXX()
    private byte[] IV=null;

    // set with initXXX()
    private CipherContextProxy contextProxy = null;

    // modified by various operations
    private int state=UNINITIALIZED;

    // States
    private static final int UNINITIALIZED=0;
    private static final int ENCRYPT=1;
    private static final int DECRYPT=2;

    private PK11Cipher() { }

    PK11Cipher(PK11Token token, EncryptionAlgorithm algorithm) {
        this.token = token;
        this.algorithm = algorithm;
    }

    public void initEncrypt(SymmetricKey key)
        throws InvalidKeyException, InvalidAlgorithmParameterException,
        TokenException
    {
        initEncrypt(key, null);
    }

    public void initDecrypt(SymmetricKey key)
        throws InvalidKeyException, InvalidAlgorithmParameterException,
        TokenException
    {
        initDecrypt(key, null);
    }

    private static byte[] getIVFromParams(AlgorithmParameterSpec params) {
        byte[] IV = null;
        if( params instanceof IVParameterSpec ) {
            IV = ((IVParameterSpec)params).getIV();
        } else if( params instanceof IvParameterSpec ) {
            IV = ((IvParameterSpec)params).getIV();
        } else if( params instanceof RC2ParameterSpec ) {
            IV = ((RC2ParameterSpec)params).getIV();
        }
        return IV;
    }


    /**
     * @deprecated isPadded() in EncryptionAlgorithm has been deprecated
     */
    @Deprecated
    public void initEncrypt(SymmetricKey key, AlgorithmParameterSpec parameters)
        throws InvalidKeyException, InvalidAlgorithmParameterException,
        TokenException
    {
        reset();

        checkKey(key);
        checkParams(parameters);

        IV = getIVFromParams(parameters);
        this.key = key;
        this.parameters = parameters;
        state = ENCRYPT;

        if( parameters instanceof RC2ParameterSpec ) {
            contextProxy = initContextWithKeyBits(
                true, key, algorithm, IV,
                ((RC2ParameterSpec)parameters).getEffectiveKeyBits(),
                algorithm.isPadded());
        } else {
            contextProxy = initContext(
                true, key, algorithm, IV, algorithm.isPadded());
        }
    }

    /**
     * @deprecated isPadded() in EncryptionAlgorithm has been deprecated
     */
    @Deprecated
    public void initDecrypt(SymmetricKey key, AlgorithmParameterSpec parameters)
        throws InvalidKeyException, InvalidAlgorithmParameterException,
        TokenException
    {
        reset();

        checkKey(key);
        checkParams(parameters);

        IV = getIVFromParams(parameters);
        this.key = key;
        this.parameters = parameters;
        state = DECRYPT;

        if( parameters instanceof RC2ParameterSpec ) {
            contextProxy = initContextWithKeyBits(
                false, key, algorithm, IV,
                ((RC2ParameterSpec)parameters).getEffectiveKeyBits(),
                algorithm.isPadded());
        } else {
            contextProxy = initContext(
                false, key, algorithm, IV, algorithm.isPadded());
        }
    }

    public byte[] update(byte[] bytes)
        throws IllegalStateException, TokenException
    {
        if( state == UNINITIALIZED ) {
            throw new IllegalStateException();
        }

        return updateContext( contextProxy, bytes, algorithm.getBlockSize());
    }

    public byte[] update(byte[] bytes, int offset, int length)
        throws IllegalStateException, TokenException
    {
        byte[] sub = new byte[length];

        System.arraycopy( bytes, offset, sub, 0, length );

        return update(sub);
    }

    /**
     * @deprecated isPadded() in EncryptionAlgorithm has been deprecated
     */
    @Deprecated
    public byte[] doFinal(byte[] bytes)
        throws IllegalStateException, IllegalBlockSizeException,
        BadPaddingException, TokenException
    {
        if( state == UNINITIALIZED ) {
            throw new IllegalStateException();
        }

        byte[] first = update(bytes);

        byte[] last = finalizeContext(contextProxy, algorithm.getBlockSize(),
                    algorithm.isPadded() );

        byte[] combined = new byte[ first.length+last.length ];
        System.arraycopy(first, 0, combined, 0, first.length);
        System.arraycopy(last, 0, combined, first.length, last.length);
        return combined;
    }

    public byte[] doFinal(byte[] bytes, int offset, int length)
        throws IllegalStateException, IllegalBlockSizeException,
        BadPaddingException, TokenException
    {
        byte[] sub = new byte[length];

        System.arraycopy(bytes, offset, sub, 0, length);

        return doFinal(sub);
    }

    /**
     * @deprecated isPadded() in EncryptionAlgorithm has been deprecated
     */
    @Deprecated
    public byte[] doFinal()
        throws IllegalStateException, IllegalBlockSizeException,
        BadPaddingException, TokenException
    {
        if( state == UNINITIALIZED ) {
            throw new IllegalStateException();
        }
        return finalizeContext(contextProxy, algorithm.getBlockSize(),
                    algorithm.isPadded() );
    }

    private static native CipherContextProxy
    initContext(boolean encrypt, SymmetricKey key, EncryptionAlgorithm alg,
                 byte[] IV, boolean padded)
        throws TokenException;

    // This version accepts the number of effective key bits for RC2 CBC.
    private static native CipherContextProxy
    initContextWithKeyBits(boolean encrypt, SymmetricKey key,
                EncryptionAlgorithm alg, byte[] IV, int keyBits, boolean padded)
        throws TokenException;

    private static native byte[]
    updateContext( CipherContextProxy context, byte[] input, int blocksize )
        throws TokenException;

    private static native byte[]
    finalizeContext( CipherContextProxy context, int blocksize, boolean padded)
        throws TokenException, IllegalBlockSizeException, BadPaddingException;

    private void reset() {
        parameters = null;
        key = null;
        IV = null;
        state = UNINITIALIZED;
        contextProxy = null;
    }

    /**
     * Matches the params against those expected by the algorithm.
     */
    private void checkParams(AlgorithmParameterSpec params)
        throws InvalidAlgorithmParameterException
    {
        if( ! algorithm.isValidParameterObject(params) ) {
            String name = "null";
            if( params != null ) {
                name = params.getClass().getName();
            }
            throw new InvalidAlgorithmParameterException(algorithm +
                " cannot use a " + name + " parameter");
        }
    }



    /**
     * Checks for null, makes sure the key lives on the correct token,
     * makes sure it is a PKCS #11 key, makes sure it's the right type
     * for this algorithm.
     */
    private void checkKey(SymmetricKey key) throws InvalidKeyException {
        if( key==null ) {
            throw new InvalidKeyException("Key is null");
        }
        if( ! (key instanceof PK11SymKey) ) {
            throw new InvalidKeyException("Key is not a PKCS #11 key");
        }

        try {
            KeyType keyType = ((PK11SymKey) key).getKeyType();
            if (
                keyType != KeyType.GENERIC_SECRET
                && keyType != KeyType.getKeyTypeFromAlgorithm(algorithm)
            ) {
                throw new InvalidKeyException("Key is not the right type for"+
                    " this algorithm. Got: " + ((PK11SymKey)key).getKeyType() + " Expected: " + KeyType.getKeyTypeFromAlgorithm(algorithm));
            }
        } catch( NoSuchAlgorithmException e ) {
            throw new RuntimeException("Unknown algorithm: " + algorithm, e);
        }
    }

    @Override
    public void finalize() throws Throwable {
        close();
    }

    @Override
    public void close() throws Exception {
        if (contextProxy != null) {
            try {
                contextProxy.close();
            } finally {
                contextProxy = null;
            }
        }
    }
}
