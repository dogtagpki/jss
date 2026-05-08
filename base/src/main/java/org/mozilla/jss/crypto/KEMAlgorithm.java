//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.mozilla.jss.crypto;

import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;

/**
 * Represents a Key Encapsulation Mechanism (KEM) algorithm.
 *
 * KEM is a cryptographic primitive used to establish a shared secret between two parties,
 * typically for key exchange. Unlike traditional key exchange mechanisms, KEM algorithms
 * are designed to be secure against quantum computer attacks.
 *
 * This class currently supports ML-KEM (Module-Lattice-based Key Encapsulation Mechanism)
 * variants, which are post-quantum cryptography algorithms standardized in FIPS 203.
 * ML-KEM was previously known as CRYSTALS-Kyber.
 *
 * Each KEM algorithm has associated parameters including:
 * <ul>
 *   <li>Secret size - the size of the shared secret generated</li>
 *   <li>Cipher size - the size of the encapsulated ciphertext</li>
 * </ul>
 *
 * @see #MLKEM512
 * @see #MLKEM768
 * @see #MLKEM1024
 */
public class KEMAlgorithm extends Algorithm {
    private static final Map<OBJECT_IDENTIFIER, KEMAlgorithm> oidMap = new HashMap<>();
    private int secretSize;
    private int cipherSize;

    public KEMAlgorithm(int oidIndex, String name, OBJECT_IDENTIFIER oid,
            int secretSize, int cipherSize) {
        super(oidIndex, name, oid);
        KEMAlgorithm newAlg = oidMap.put(oid, this);
        if (newAlg != null) {
            throw new IllegalArgumentException("Duplicate KEM OID: " + oid.toDottedString());
        }
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

    /**
     * ML-KEM-512 algorithm providing security level 1 (equivalent to AES-128).
     * <ul>
     *   <li>OID: 2.16.840.1.101.3.4.4.1</li>
     *   <li>Secret size: 32 bytes</li>
     *   <li>Ciphertext size: 768 bytes</li>
     * </ul>
     */
    public static final KEMAlgorithm
            MLKEM512 = new KEMAlgorithm(CKM_ML_KEM, "ML-KEM-512",
                    OBJECT_IDENTIFIER.KEM_ALGORITHM.subBranch(1),
                    32, 768
            );

    /**
     * ML-KEM-768 algorithm providing security level 3 (equivalent to AES-192).
     * <ul>
     *   <li>OID: 2.16.840.1.101.3.4.4.2</li>
     *   <li>Secret size: 32 bytes</li>
     *   <li>Ciphertext size: 1088 bytes</li>
     * </ul>
     */
    public static final KEMAlgorithm
            MLKEM768 = new KEMAlgorithm(CKM_ML_KEM, "ML-KEM-768",
                    OBJECT_IDENTIFIER.KEM_ALGORITHM.subBranch(2),
                    32, 1088
            );

    /**
     * ML-KEM-1024 algorithm providing security level 5 (equivalent to AES-256).
     * <ul>
     *   <li>OID: 2.16.840.1.101.3.4.4.3</li>
     *   <li>Secret size: 32 bytes</li>
     *   <li>Ciphertext size: 1568 bytes</li>
     * </ul>
     */
    public static final KEMAlgorithm
            MLKEM1024 = new KEMAlgorithm(CKM_ML_KEM, "ML-KEM-1024",
                    OBJECT_IDENTIFIER.KEM_ALGORITHM.subBranch(3),
                    32, 1568
            );

}
