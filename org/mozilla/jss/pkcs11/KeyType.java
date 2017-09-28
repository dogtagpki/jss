/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkcs11;

import org.mozilla.jss.crypto.Algorithm;
import org.mozilla.jss.crypto.HMACAlgorithm;
import java.util.Hashtable;
import org.mozilla.jss.util.*;
import java.security.NoSuchAlgorithmException;
import org.mozilla.jss.crypto.SignatureAlgorithm;
import org.mozilla.jss.crypto.KeyWrapAlgorithm;
import org.mozilla.jss.crypto.EncryptionAlgorithm;

/**
 * PKCS #11 Key Types
 * These are the possible types for keys in the
 * wrapper library.
 * Key types are implemented as flyweights.
 *
 * Although the KeyType class is public, it should
 * be considered private. We made the KeyType class
 * public so that we can force it to load during
 * CryptoManager.initialize(), before we install JSS
 * as a provider.
**/
public final class KeyType {
    protected KeyType() {}

    protected KeyType(Algorithm[] algs, String name) {
        int i;

        Assert._assert(algs!=null);

        algorithms = (Algorithm[]) algs.clone();

        // Register this key as the key type for each of its algorithms
        for(i=0; i < algorithms.length; i++) {
            Assert._assert(! algHash.containsKey(algorithms[i]) );
            algHash.put(algorithms[i], this);
        }
        this.name = name;
    }

    /**
     * Returns an array of algorithms supported by this key type.
     */
    public Algorithm[] supportedAlgorithms() {
        return algorithms;
    }

    /**
     * Returns the KeyType corresponding to the given Algorithm.  If there
     * is no KeyType registered for this algorithm, a NoSuchAlgorithmException
     * is thrown.
     */
    static public KeyType getKeyTypeFromAlgorithm(Algorithm alg)
        throws NoSuchAlgorithmException
    {
        Assert._assert(alg!=null);
        Object obj = algHash.get(alg);

        if(obj == null) {
            throw new NoSuchAlgorithmException();
        }

        Assert._assert( obj instanceof KeyType );

        return (KeyType) obj;
    }

    public String toString() {
        return name;
    }


    //////////////////////////////////////////////////////////////
    // Instance Data
    //////////////////////////////////////////////////////////////

    // An array of algorithms supported by this key type
    protected Algorithm[] algorithms;

    protected String name;


    //////////////////////////////////////////////////////////////
    // Class Data
    //////////////////////////////////////////////////////////////

    // A hash table associating a key type with each algorithm
    static protected Hashtable algHash;
    static {
        algHash = new Hashtable();
    }




    //////////////////////////////////////////////////////////////
    // Key Types
    //////////////////////////////////////////////////////////////

    //////////////////////////////////////////////////////////////
    static public final KeyType
    NULL    = new KeyType(new Algorithm[0], "NULL");

    //////////////////////////////////////////////////////////////
    static public final KeyType
    RSA     = new KeyType (new Algorithm[]
                    {
                    SignatureAlgorithm.RSASignature,
                    SignatureAlgorithm.RSASignatureWithMD2Digest,
                    SignatureAlgorithm.RSASignatureWithMD5Digest,
                    SignatureAlgorithm.RSASignatureWithSHA1Digest,
                    SignatureAlgorithm.RSASignatureWithSHA256Digest,
                    SignatureAlgorithm.RSASignatureWithSHA384Digest,
                    SignatureAlgorithm.RSASignatureWithSHA512Digest,
                    KeyWrapAlgorithm.RSA
                    },
                    "RSA"
                );

    //////////////////////////////////////////////////////////////
    static public final KeyType
    DSA     = new KeyType(new Algorithm[]
                    {
                    SignatureAlgorithm.DSASignature,
                    SignatureAlgorithm.DSASignatureWithSHA1Digest
                    },
                    "DSA"
                );

    //////////////////////////////////////////////////////////////
    static public final KeyType
    EC     = new KeyType(new Algorithm[]
                    {
                    SignatureAlgorithm.ECSignature,
                    SignatureAlgorithm.ECSignatureWithSHA1Digest,
                    SignatureAlgorithm.ECSignatureWithSHA256Digest,
                    SignatureAlgorithm.ECSignatureWithSHA384Digest,
                    SignatureAlgorithm.ECSignatureWithSHA512Digest
                    },
                    "EC"
                );

    //////////////////////////////////////////////////////////////
    /**
     * @deprecated As of NSS 3.11, FORTEZZA is no longer supported.
     * This is just a placeholder for backward compatibility.
     */
    static public final KeyType
    FORTEZZA = new KeyType(new Algorithm[0], "FORTEZZA");

    //////////////////////////////////////////////////////////////
    static public final KeyType
    DH      = new KeyType(new Algorithm[0], "DH");

    //////////////////////////////////////////////////////////////
    static public final KeyType
    KEA     = new KeyType(new Algorithm[0], "KEA");

    //////////////////////////////////////////////////////////////
    static public final KeyType
    DES     = new KeyType(new Algorithm[]
                            {
                            KeyWrapAlgorithm.DES_ECB,
                            KeyWrapAlgorithm.DES_CBC,
                            KeyWrapAlgorithm.DES_CBC_PAD,
                            EncryptionAlgorithm.DES_ECB,
                            EncryptionAlgorithm.DES_CBC,
                            EncryptionAlgorithm.DES_CBC_PAD
                            },
                            "DES"
                        );

    //////////////////////////////////////////////////////////////
    static public final KeyType
    DES3     = new KeyType(new Algorithm[]
                            {
                            KeyWrapAlgorithm.DES3_ECB,
                            KeyWrapAlgorithm.DES3_CBC,
                            KeyWrapAlgorithm.DES3_CBC_PAD,
                            EncryptionAlgorithm.DES3_ECB,
                            EncryptionAlgorithm.DES3_CBC,
                            EncryptionAlgorithm.DES3_CBC_PAD
                            },
                            "DESede"
                        );

    //////////////////////////////////////////////////////////////
    static public final KeyType
    AES       = new KeyType(new Algorithm[]
                            {
                            KeyWrapAlgorithm.AES_ECB,
                            KeyWrapAlgorithm.AES_CBC,
                            KeyWrapAlgorithm.AES_CBC_PAD,
                            KeyWrapAlgorithm.AES_KEY_WRAP,
                            KeyWrapAlgorithm.AES_KEY_WRAP_PAD,
                            EncryptionAlgorithm.AES_128_ECB,
                            EncryptionAlgorithm.AES_128_CBC,
                            EncryptionAlgorithm.AES_192_ECB,
                            EncryptionAlgorithm.AES_192_CBC,
                            EncryptionAlgorithm.AES_256_ECB,
                            EncryptionAlgorithm.AES_256_CBC,
                            EncryptionAlgorithm.AES_CBC_PAD, 
                            EncryptionAlgorithm.AES_128_CBC_PAD,
                            EncryptionAlgorithm.AES_192_CBC_PAD,
                            EncryptionAlgorithm.AES_256_CBC_PAD        
                            },
                            "AES"
                        );

    //////////////////////////////////////////////////////////////
    static public final KeyType
    RC4     = new KeyType(new Algorithm[]
                            {
                            EncryptionAlgorithm.RC4
                            },
                            "RC4"
                        );

    //////////////////////////////////////////////////////////////
    static public final KeyType
    RC2     = new KeyType(new Algorithm[]
                            {
                            EncryptionAlgorithm.RC2_CBC,
                            EncryptionAlgorithm.RC2_CBC_PAD
                            },
                            "RC2"
                        );

    //////////////////////////////////////////////////////////////
    static public final KeyType
    SHA1_HMAC = new KeyType(new Algorithm[]
                            {
                            HMACAlgorithm.SHA1
                            },
                            "SHA1_HMAC"
                        );

    static public final KeyType GENERIC_SECRET =
        new KeyType(new Algorithm[] { }, "GENERIC_SECRET");

}
