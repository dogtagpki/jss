/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.crypto;

import java.util.Hashtable;
import org.mozilla.jss.asn1.*;
import java.security.NoSuchAlgorithmException;

/**
 * Algorithms for performing HMACs. These can be used to create
 * MessageDigests.
 */
public class HMACAlgorithm extends DigestAlgorithm {

    protected HMACAlgorithm(int oidIndex, String name, OBJECT_IDENTIFIER oid,
                int outputSize) {
        super(oidIndex, name, oid, outputSize);

        if( oid!=null && oidMap.get(oid)==null) {
            oidMap.put(oid, this);
        }
    }

    ///////////////////////////////////////////////////////////////////////
    // OID mapping
    ///////////////////////////////////////////////////////////////////////
    private static Hashtable oidMap = new Hashtable();

    /**
     * Looks up the HMAC algorithm with the given OID.
     * 
     * @exception NoSuchAlgorithmException If no registered HMAC algorithm
     *  has the given OID.
     */
    public static DigestAlgorithm fromOID(OBJECT_IDENTIFIER oid)
        throws NoSuchAlgorithmException
    {
        Object alg = oidMap.get(oid);
        if( alg == null ) {
            throw new NoSuchAlgorithmException();
        } else {
            return (HMACAlgorithm) alg;
        }
    }

    /**
     * SHA-X HMAC.  This is a Message Authentication Code that uses a
     * symmetric key together with SHA-X digesting to create a form of
     * signature.
     */
    public static final HMACAlgorithm SHA1 = new HMACAlgorithm
        (CKM_SHA_1_HMAC, "SHA-1-HMAC",
             OBJECT_IDENTIFIER.ALGORITHM.subBranch(26), 20);

    public static final HMACAlgorithm SHA256 = new HMACAlgorithm
        (SEC_OID_HMAC_SHA256, "SHA-256-HMAC",
             OBJECT_IDENTIFIER.RSA_DIGEST.subBranch(9), 32);

    public static final HMACAlgorithm SHA384 = new HMACAlgorithm
        (SEC_OID_HMAC_SHA384, "SHA-384-HMAC",
             OBJECT_IDENTIFIER.RSA_DIGEST.subBranch(10), 48);

    public static final HMACAlgorithm SHA512 = new HMACAlgorithm
        (SEC_OID_HMAC_SHA512, "SHA-512-HMAC",
             OBJECT_IDENTIFIER.RSA_DIGEST.subBranch(11), 64);

}
