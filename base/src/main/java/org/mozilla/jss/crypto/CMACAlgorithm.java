/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.crypto;

import java.security.NoSuchAlgorithmException;
import java.util.Hashtable;

import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;

/**
 * Algorithms for performing CMACs. These can be used to create
 * MessageDigests.
 */
public class CMACAlgorithm extends DigestAlgorithm {

    protected CMACAlgorithm(int oidIndex, String name, OBJECT_IDENTIFIER oid,
                            int outputSize) {
        super(oidIndex, name, oid, outputSize);

        if (oid != null && oidMap.get(oid) == null) {
            oidMap.put(oid, this);
        }
    }

    ///////////////////////////////////////////////////////////////////////
    // OID mapping
    ///////////////////////////////////////////////////////////////////////
    private static Hashtable<OBJECT_IDENTIFIER, CMACAlgorithm> oidMap = new Hashtable<>();

    /**
     * Looks up the CMAC algorithm with the given OID.
     *
     * @param oid OID.
     * @return CMAC algorithm.
     * @exception NoSuchAlgorithmException If no registered CMAC algorithm
     *  has the given OID.
     */
    public static CMACAlgorithm fromOID(OBJECT_IDENTIFIER oid)
        throws NoSuchAlgorithmException
    {
        CMACAlgorithm alg = oidMap.get(oid);
        if (alg == null) {
            throw new NoSuchAlgorithmException("No such algorithm for OID: " + oid);
        }

        return alg;
    }

    /**
     * CMAC AES-X.  This is a Message Authentication Code that uses a
     * symmetric key together with the AES cipher to create a form of
     * signature.
     *
     * Note that we pass null for the OID here: neither NIST nor any other
     * standards body has defined an OID for use with CMAC. Since we use
     * a PKCS#11 backend and NSS doesn't otherwise define CMAC based on a
     * SEC OID, we don't strictly need one.
     *
     * We've left the fromOID code (and oid parameter in the constructor) as
     * other projects use them for HMACAlgorith. At such time as an OID is
     * defined, it can be added here.
     */
    public static final CMACAlgorithm AES = new CMACAlgorithm(CKM_AES_CMAC, "AES-CMAC", null, 16);
    public static final CMACAlgorithm AES128 = AES;
    public static final CMACAlgorithm AES192 = AES;
    public static final CMACAlgorithm AES256 = AES;
}
