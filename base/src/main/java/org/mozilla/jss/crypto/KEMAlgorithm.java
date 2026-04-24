//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.mozilla.jss.crypto;

import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;

/**
 *
 */
public class KEMAlgorithm extends Algorithm {
    private static HashMap<OBJECT_IDENTIFIER, KEMAlgorithm> oidMap = new HashMap<>();
    private KEMAlgorithm kemAlg;
    private int secretSize;
    private int cipherSize;

    public KEMAlgorithm(int oidIndex, String name, OBJECT_IDENTIFIER oid,
            int secretSize, int cipherSize) {
        super(oidIndex, name, oid);
        this.kemAlg = this;
        oidMap.put(oid, this);
        this.secretSize = secretSize;
        this.cipherSize = cipherSize;
    }

    public int getSecretSize() {
        return secretSize;
    }

    public int getCipherSize() {
        return cipherSize;
    }

    public static KEMAlgorithm fromOID(OBJECT_IDENTIFIER oid)
            throws NoSuchAlgorithmException
    {
        KEMAlgorithm alg = oidMap.get(oid);
        if( alg == null ) {
            throw new NoSuchAlgorithmException();
        }
        return alg;
    }

    public static final KEMAlgorithm
            MLKEM512 = new KEMAlgorithm(CKM_ML_KEM, "ML-KEM-512",
                    OBJECT_IDENTIFIER.KEM_ALGORITHM.subBranch(1),
                    32, 768
            );

    public static final KEMAlgorithm
            MLKEM768 = new KEMAlgorithm(CKM_ML_KEM, "ML-KEM-768",
                    OBJECT_IDENTIFIER.KEM_ALGORITHM.subBranch(2),
                    32, 1088
            );

    public static final KEMAlgorithm
            MLKEM1024 = new KEMAlgorithm(CKM_ML_KEM, "ML-KEM-1024",
                    OBJECT_IDENTIFIER.KEM_ALGORITHM.subBranch(3),
                    32, 1568
            );

}
