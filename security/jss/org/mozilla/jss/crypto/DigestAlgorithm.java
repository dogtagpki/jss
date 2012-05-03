/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.crypto;

import java.util.Hashtable;
import java.security.NoSuchAlgorithmException;
import org.mozilla.jss.asn1.*;

public class DigestAlgorithm extends Algorithm {

    // The size in bytes of the output of this hash.
    private int outputSize;

    protected DigestAlgorithm(int oidIndex, String name,
            OBJECT_IDENTIFIER oid, int outputSize)
    {
        super(oidIndex, name, oid);

        this.outputSize = outputSize;

        // only store the first algorithm for a given oid.  More than one
        // alg might share the same oid, such as from child classes.
        if( oid != null && oidMap.get(oid)==null ) {
            oidMap.put(oid, this);
        }
    }

    ///////////////////////////////////////////////////////////////////////
    // OID mapping
    ///////////////////////////////////////////////////////////////////////
    private static Hashtable oidMap = new Hashtable();

    public static DigestAlgorithm fromOID(OBJECT_IDENTIFIER oid)
        throws NoSuchAlgorithmException
    {
        Object alg = oidMap.get(oid);
        if( alg == null ) {
            throw new NoSuchAlgorithmException();
        } else {
            return (DigestAlgorithm) alg;
        }
    }

    /**
     * Returns the output size in bytes for this algorithm.
     */
    public int getOutputSize() {
        return outputSize;
    }

    /**
     * The MD2 digest algorithm, from RSA.
     */
    public static final DigestAlgorithm MD2 = new DigestAlgorithm
        (SEC_OID_MD2, "MD2", OBJECT_IDENTIFIER.RSA_DIGEST.subBranch(2), 16 );

    /**
     * The MD5 digest algorithm, from RSA.
     */
    public static final DigestAlgorithm MD5 = new DigestAlgorithm
        (SEC_OID_MD5, "MD5", OBJECT_IDENTIFIER.RSA_DIGEST.subBranch(5), 16 );

    /**
     * The SHA-1 digest algorithm, from Uncle Sam.
     */
    public static final DigestAlgorithm SHA1 = new DigestAlgorithm
        (SEC_OID_SHA1, "SHA-1", OBJECT_IDENTIFIER.ALGORITHM.subBranch(26), 20);

    /*
    * The SHA-256 digest Algorithm from FIPS 180-2  
    */
    public static final DigestAlgorithm SHA256 = new DigestAlgorithm
        (SEC_OID_SHA256, "SHA-256", OBJECT_IDENTIFIER.HASH_ALGORITHM.subBranch(1), 32);

    /*
    * The SHA-384 digest Algorithm from FIPS 180-2  
    */
    public static final DigestAlgorithm SHA384 = new DigestAlgorithm
        (SEC_OID_SHA384, "SHA-384", OBJECT_IDENTIFIER.HASH_ALGORITHM.subBranch(2), 48);

    /*
    * The SHA-512 digest Algorithm from FIPS 180-2  
    */
    public static final DigestAlgorithm SHA512 = new DigestAlgorithm
        (SEC_OID_SHA512, "SHA-512", OBJECT_IDENTIFIER.HASH_ALGORITHM.subBranch(3), 64);

}
