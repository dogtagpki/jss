/* 
 * The contents of this file are subject to the Mozilla Public
 * License Version 1.1 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of
 * the License at http://www.mozilla.org/MPL/
 * 
 * Software distributed under the License is distributed on an "AS
 * IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * rights and limitations under the License.
 * 
 * The Original Code is the Netscape Security Services for Java.
 * 
 * The Initial Developer of the Original Code is Netscape
 * Communications Corporation.  Portions created by Netscape are 
 * Copyright (C) 1998-2000 Netscape Communications Corporation.  All
 * Rights Reserved.
 * 
 * Contributor(s):
 * 
 * Alternatively, the contents of this file may be used under the
 * terms of the GNU General Public License Version 2 or later (the
 * "GPL"), in which case the provisions of the GPL are applicable 
 * instead of those above.  If you wish to allow use of your 
 * version of this file only under the terms of the GPL and not to
 * allow others to use your version of this file under the MPL,
 * indicate your decision by deleting the provisions above and
 * replace them with the notice and other provisions required by
 * the GPL.  If you do not delete the provisions above, a recipient
 * may use your version of this file under either the MPL or the
 * GPL.
 */

package org.mozilla.jss.pkcs11;

import org.mozilla.jss.crypto.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import org.mozilla.jss.util.Assert;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.DSAPublicKey;

final class PK11KeyWrapper implements KeyWrapper {

    private PK11Token token;
    private KeyWrapAlgorithm algorithm;
    private int state=UNINITIALIZED;
    private AlgorithmParameterSpec parameters=null;
    private SymmetricKey symKey=null;
    private PrivateKey privKey=null;
    private PublicKey pubKey=null;
    private byte[] IV=null;

    // states
    private static final int UNINITIALIZED=0;
    private static final int WRAP=1;
    private static final int UNWRAP=2;

    private PK11KeyWrapper() { }

    PK11KeyWrapper(PK11Token token, KeyWrapAlgorithm algorithm) {
        this.token = token;
        this.algorithm = algorithm;
    }

    public void initWrap(SymmetricKey wrappingKey,
                    AlgorithmParameterSpec parameters)
        throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        initWrap(parameters);
        checkWrapper(wrappingKey);
        this.symKey = wrappingKey;
    }

    public void initWrap(PublicKey wrappingKey,
                            AlgorithmParameterSpec parameters)
            throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        initWrap(parameters);
        checkWrapper(wrappingKey);
        this.pubKey = wrappingKey;
    }

    /**
     * Does everything that is key-independent for initializing a wrap.
     */
    private void initWrap(AlgorithmParameterSpec parameters)
        throws InvalidAlgorithmParameterException
    {
        reset();

        checkParams(parameters);

        this.parameters = parameters;
        state = WRAP;
    }

    public void initUnwrap(PrivateKey unwrappingKey,
                    AlgorithmParameterSpec parameters)
        throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        initUnwrap(parameters);
        checkWrapper(unwrappingKey);
        this.privKey = unwrappingKey;
    }

    public void initUnwrap(SymmetricKey unwrappingKey,
                    AlgorithmParameterSpec parameters)
        throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        initUnwrap(parameters);
        checkWrapper(unwrappingKey);
        this.symKey = unwrappingKey;
    }

    /**
     * Does the key-independent parts of initializing an unwrap.
     */
    private void initUnwrap(AlgorithmParameterSpec parameters)
        throws InvalidAlgorithmParameterException
    {
        reset();

        checkParams(parameters);

        this.parameters = parameters;
        state = UNWRAP;
    }

    /**
     * Makes sure the key is right for the algorithm.
     */
    private void checkWrapper(PublicKey key) throws InvalidKeyException {
        if( key==null ) {
            throw new InvalidKeyException("Key is null");
        }
        if( ! (key instanceof PK11PubKey) ) {
            throw new InvalidKeyException("Key is not a PKCS #11 key");
        }
        try {
            KeyType type = KeyType.getKeyTypeFromAlgorithm(algorithm);
            if( (type == KeyType.RSA && !(key instanceof RSAPublicKey)) ||
                (type == KeyType.DSA && !(key instanceof DSAPublicKey)) ) {
                throw new InvalidKeyException("Key is not the right type for "+
                    "this algorithm");
            }
        } catch( NoSuchAlgorithmException e ) {
            Assert.notReached("unable to find algorithm from key type");
        }
    }

    /**
     * Makes sure the key lives on the token and is right for the algorithm.
     */
    private void checkWrapper(SymmetricKey key)
        throws InvalidKeyException
    {
        if( key==null ) {
            throw new InvalidKeyException("Key is null");
        }
        if( ! key.getOwningToken().equals(token) ) {
            throw new InvalidKeyException("Key does not reside on the "+
                "current token");
        }
        if( ! (key instanceof PK11SymKey) ) {
            throw new InvalidKeyException("Key is not a PKCS #11 key");
        }
        try {
            if( ((PK11SymKey)key).getKeyType() !=
                    KeyType.getKeyTypeFromAlgorithm(algorithm) ) {
                throw new InvalidKeyException("Key is not the right type for"+
                    " this algorithm");
            }
        } catch( NoSuchAlgorithmException e ) {
            Assert.notReached("Unknown algorithm");
        }
    }

    /**
     * Makes sure the key is on the token and is right for the algorithm.
     */
    private void checkWrapper(PrivateKey key)
        throws InvalidKeyException
    {
        if( key==null ) {
            throw new InvalidKeyException("Key is null");
        }
        if( ! key.getOwningToken().equals(token) ) {
            throw new InvalidKeyException("Key does not reside on the "+
                "current token");
        }
        if( ! (key instanceof PK11PrivKey) ) {
            throw new InvalidKeyException("Key is not a PKCS #11 key");
        }
        try {
            if( ((PK11PrivKey)key).getKeyType() !=
                    KeyType.getKeyTypeFromAlgorithm(algorithm) ) {
                throw new InvalidKeyException("Key is not the right type for"+
                    " this algorithm");
            }
        } catch( NoSuchAlgorithmException e ) {
            Assert.notReached("Unknown algorithm");
        }
    }

    private void checkParams(AlgorithmParameterSpec params)
        throws InvalidAlgorithmParameterException
    {
        Class paramClass = algorithm.getParameterClass();
        if(params==null) {
            if(paramClass != null) {
                // this algorithm takes a parameter, but none was given
                throw new InvalidAlgorithmParameterException(algorithm+
                    " requires an algorithm parameter");
            }
        } else {
            if( paramClass == null ) {
                //this algorithm doesn't take a param, but one was given
                throw new InvalidAlgorithmParameterException(algorithm+
                    " does not take a parameter");
            } else if( ! ( paramClass.isInstance(params) ) ) {
                throw new InvalidAlgorithmParameterException(algorithm+
                    " expects a parameter of type "+paramClass);
            }

            if( params instanceof IVParameterSpec ) {
                IV = ((IVParameterSpec)params).getIV();
            }
        }
    }

    public byte[]
    wrap(PrivateKey toBeWrapped)
        throws InvalidKeyException, IllegalStateException, TokenException
    {
        if( state != WRAP ) {
            throw new IllegalStateException();
        }

        checkWrappee(toBeWrapped);

        if( symKey != null ) {
            Assert.assert( privKey==null && pubKey==null );
            return nativeWrapPrivWithSym(token, toBeWrapped, symKey, algorithm,
                IV);
        } else {
            throw new InvalidKeyException(
                "Wrapping a private key with a public key is not supported");
            /*
            Assert.assert( pubKey!=null && privKey==null && symKey==null );
            return nativeWrapPrivWithPub(token, toBeWrapped, pubKey, algorithm,
                    IV);
            */
        }
    }

    public byte[]
    wrap(SymmetricKey toBeWrapped)
        throws InvalidKeyException, IllegalStateException, TokenException
    {
        if( state != WRAP ) {
            throw new IllegalStateException();
        }

        checkWrappee(toBeWrapped);

        if( symKey != null ) {
            Assert.assert( privKey==null && pubKey==null );
            return nativeWrapSymWithSym(token, toBeWrapped, symKey, algorithm,
                        IV);
        } else {
            Assert.assert( pubKey!=null && privKey==null && symKey==null );
            return nativeWrapSymWithPub(token, toBeWrapped, pubKey, algorithm,
                        IV);
        }
    }

    /**
     * Makes sure the key lives on the right token.
     */
    private void
    checkWrappee(SymmetricKey symKey) throws InvalidKeyException {
        if( symKey == null ) {
            throw new InvalidKeyException("key to be wrapped is null");
        }
        if( ! (symKey instanceof PK11SymKey) ) {
            throw new InvalidKeyException("key to be wrapped is not a "+
                "PKCS #11 key");
        }
        if( ! symKey.getOwningToken().equals(token) ) {
            throw new InvalidKeyException("key to be wrapped does not live"+
                " on the same token as the wrapping key");
        }
    }

    /**
     * Makes sure the key lives on the right token.
     */
    private void
    checkWrappee(PrivateKey privKey) throws InvalidKeyException {
        if( privKey == null ) {
            throw new InvalidKeyException("key to be wrapped is null");
        }
        if( ! (privKey instanceof PK11PrivKey) ) {
            throw new InvalidKeyException("key to be wrapped is not a "+
                "PKCS #11 key");
        }
        if( ! privKey.getOwningToken().equals(token) ) {
            throw new InvalidKeyException("key to be wrapped does not live"+
                " on the same token as the wrapping key");
        }
    }

    /**
     * Wrap a symmetric with a symmetric
     */
    private static native byte[]
    nativeWrapSymWithSym(PK11Token token, SymmetricKey toBeWrapped, 
        SymmetricKey wrappingKey, KeyWrapAlgorithm alg, byte[] IV)
            throws TokenException;

    /**
     * Wrap a symmetric with a public
     */
    private static native byte[]
    nativeWrapSymWithPub(PK11Token token, SymmetricKey toBeWrapped,
        PublicKey wrappingKey, KeyWrapAlgorithm alg, byte[] IV)
            throws TokenException;

    /**
     * Wrap a private with a symmetric
     */
    private static native byte[]
    nativeWrapPrivWithSym(PK11Token token, PrivateKey toBeWrapped,
        SymmetricKey wrappingKey, KeyWrapAlgorithm alg, byte[] IV)
            throws TokenException;

    /**
     * Wrap a private with a public.
     * NOTE: This operation is not supported by the security library.
    private static native byte[]
    nativeWrapPrivWithPub(PK11Token token, PrivateKey toBeWrapped,
        PublicKey wrappingKey,
        KeyWrapAlgorithm alg, byte[] IV)
            throws TokenException;
     */

    /**
     * Unwraps a private key, creating a permanent private key object.
     * A permanent private key object resides on a token until it is
     * explicitly deleted from the token.
     */
    public PrivateKey
    unwrapPrivate(byte[] wrapped, PrivateKey.Type type, PublicKey publicKey)
        throws TokenException, InvalidKeyException, IllegalStateException
    {
        return baseUnwrapPrivate(wrapped, type, publicKey, false);
    }

    /**
     * Unwraps a private key, creating a temporary private key object.
     * A temporary
     * private key is one that does not permanently reside on a token.  
     * As soon as it is garbage-collected, it is gone forever.
     */
    public PrivateKey
    unwrapTemporaryPrivate(byte[] wrapped, PrivateKey.Type type,
        PublicKey publicKey)
        throws TokenException, InvalidKeyException, IllegalStateException
    {
        return baseUnwrapPrivate(wrapped, type, publicKey, true);
    }

    private PrivateKey
    baseUnwrapPrivate(byte[] wrapped, PrivateKey.Type type,
            PublicKey publicKey, boolean temporary)
        throws TokenException, InvalidKeyException, IllegalStateException
    {
        if( state != UNWRAP ) {
            throw new IllegalStateException();
        }

        byte[] publicValue = extractPublicValue(publicKey, type);

        if( symKey != null ) {
            Assert.assert(pubKey==null && privKey==null);
            return nativeUnwrapPrivWithSym(token, symKey, wrapped, algorithm,
                        algFromType(type), publicValue, IV, temporary );
        } else {
            throw new InvalidKeyException("Unwrapping a private key with"
                + " a private key is not supported");
            /*
            Assert.assert(privKey!=null && pubKey==null && symKey==null);
            return nativeUnwrapPrivWithPriv(token, privKey, wrapped, algorithm,
                        algFromType(type), publicValue, IV, temporary );
            */
        }
    }

    /**
     * Extracts the "public value" from a public key.  The public value is
     *  used to construct the key identifier (CKA_ID). Also, the internal token
     *  stores the DSA public value along with the private key.
     */
    private static byte[]
    extractPublicValue(PublicKey publicKey, PrivateKey.Type type)
        throws InvalidKeyException
    {
        if( publicKey == null ) {
            throw new InvalidKeyException("publicKey is null");
        }
        if( type == PrivateKey.RSA ) {
            if( !(publicKey instanceof RSAPublicKey)) {
                throw new InvalidKeyException("Type of public key does not "+
                    "match type of private key");
            }
            return ((RSAPublicKey)publicKey).getModulus().toByteArray();
        } else if(type == PrivateKey.DSA) {
            if( !(publicKey instanceof DSAPublicKey) ) {
                throw new InvalidKeyException("Type of public key does not "+
                    "match type of private key");
            }
            return ((DSAPublicKey)publicKey).getY().toByteArray();
        } else {
            Assert.notReached("Unknown private key type");
            return new byte[] { };
        }
    }


    public SymmetricKey
    unwrapSymmetric(byte[] wrapped, SymmetricKey.Type type,
        SymmetricKey.Usage usage, int keyLen)
        throws TokenException, IllegalStateException,
            InvalidAlgorithmParameterException
    {
        if( state != UNWRAP ) {
            throw new IllegalStateException();
        }

        if( (! algorithm.isPadded()) && (type == SymmetricKey.RC4) ) {
            if( keyLen <= 0 ) {
                throw new InvalidAlgorithmParameterException(
                    "RC4 keys wrapped in unpadded algorithms need key length"+
                    " specified when unwrapping");
            }
        } else {
            // Don't use the key length
            keyLen = 0;
        }

        if( symKey != null ) {
            Assert.assert(pubKey==null && privKey==null);
            return nativeUnwrapSymWithSym(token, symKey, wrapped, algorithm,
                        algFromType(type), keyLen, IV, usage.getVal() );
        } else {
            Assert.assert(privKey!=null && pubKey==null && symKey==null);
            return nativeUnwrapSymWithPriv(token, privKey, wrapped, algorithm,
                        algFromType(type), keyLen, IV, usage.getVal() );
        }
    }

    private static Algorithm
    algFromType(PrivateKey.Type type) {
        if(type == PrivateKey.RSA) {
            return KeyPairAlgorithm.RSAFamily;
        } else {
            Assert.assert(type == PrivateKey.DSA);
            return KeyPairAlgorithm.DSAFamily;
        }
    }

    private static Algorithm
    algFromType(SymmetricKey.Type type) {
        if( type == SymmetricKey.DES ) {
            return EncryptionAlgorithm.DES_ECB;
        } else if( type == SymmetricKey.DES3 ) {
            return EncryptionAlgorithm.DES3_ECB;
        } else {
            Assert.assert( type == SymmetricKey.RC4 );
            return EncryptionAlgorithm.RC4;
        }
    }

    /**
     * Unwrap a private with a symmetric.
     */
    private static native PrivateKey
    nativeUnwrapPrivWithSym(PK11Token token, SymmetricKey unwrappingKey,
        byte[] wrappedKey, KeyWrapAlgorithm alg, Algorithm type,
        byte[] publicValue, byte[] IV, boolean temporary)
            throws TokenException;

    /**
     * Unwrap a private with a private.
     * NOTE: this is not supported by the security library.
    private static native PrivateKey
    nativeUnwrapPrivWithPriv(PK11Token token, PrivateKey unwrappingKey,
        byte[] wrappedKey, KeyWrapAlgorithm alg, Algorithm type,
        byte[] publicValue, byte[] IV, boolean temporary)
            throws TokenException;
     */

    /**
     * Unwrap a symmetric with a symmetric.
     */
    private static native SymmetricKey
    nativeUnwrapSymWithSym(PK11Token token, SymmetricKey unwrappingKey,
        byte[] wrappedKey, KeyWrapAlgorithm alg, Algorithm type, int keyLen,
        byte[] IV, int usageEnum)
            throws TokenException;

    /**
     * Unwrap a symmetric with a private.
     */
    private static native SymmetricKey
    nativeUnwrapSymWithPriv(PK11Token token, PrivateKey unwrappingKey,
        byte[] wrappedKey, KeyWrapAlgorithm alg, Algorithm type, int keyLen,
        byte[] IV, int usageEnum)
            throws TokenException;


    private void reset() {
        state = UNINITIALIZED;
        symKey = null;
        privKey = null;
        pubKey = null;
        parameters = null;
        IV = null;
    }
}
