/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.crypto;

import java.security.NoSuchAlgorithmException;
import java.util.Hashtable;

/**
 * Algorithms that can be used for keypair generation.
 */
public class KeyPairAlgorithm extends Algorithm {

    protected KeyPairAlgorithm(int oidIndex, String name, Algorithm algFamily) {
        super(oidIndex, name);
        this.algFamily = algFamily;
        nameMap.put(name, this);
    }

    /**
     * Returns the algorithm family for a given key pair generation algorithm.
     * If a token supports a family and is writable, we can do keypair gen
     * on the token even if it doesn't support the keypair gen algorithm.
     * We do this by doing the keypair gen on the internal module and then
     * moving the key out to the other token.
     */
    public Algorithm
    getAlgFamily()
    {
        return algFamily;
    }

    private static Hashtable nameMap = new Hashtable();

    /**
     * Looks up a key pair generation algorithm from its name. The names
     * are those specified in the JCA spec. For example, "RSA" and "DSA".
     *
     * @throws NoSuchAlgorithmException If the name of the algorithm is not
     *  recognized as a supported algorithm.
     */
    public static KeyPairAlgorithm fromString(String algName)
        throws NoSuchAlgorithmException
    {
        KeyPairAlgorithm alg = (KeyPairAlgorithm)nameMap.get(algName);
        if( alg == null ) {
            throw new NoSuchAlgorithmException();
        }
        return alg;
    }

    protected Algorithm algFamily;

    ////////////////////////////////////////////////////////////////
    // Key-Pair Generation Algorithms
    ////////////////////////////////////////////////////////////////
    public static final Algorithm
    RSAFamily = new Algorithm(SEC_OID_PKCS1_RSA_ENCRYPTION, "RSA");

    public static final Algorithm
    DSAFamily = new Algorithm(SEC_OID_ANSIX9_DSA_SIGNATURE, "DSA");

    public static final Algorithm
    ECFamily = new Algorithm(SEC_OID_ANSIX962_EC_PUBLIC_KEY, "EC");

    public static final KeyPairAlgorithm
    RSA = new KeyPairAlgorithm(CKM_RSA_PKCS_KEY_PAIR_GEN, "RSA", RSAFamily);

    public static final KeyPairAlgorithm
    DSA = new KeyPairAlgorithm(CKM_DSA_KEY_PAIR_GEN, "DSA", DSAFamily);

    public static final KeyPairAlgorithm
    EC = new KeyPairAlgorithm(CKM_EC_KEY_PAIR_GEN, "EC", ECFamily);
}
