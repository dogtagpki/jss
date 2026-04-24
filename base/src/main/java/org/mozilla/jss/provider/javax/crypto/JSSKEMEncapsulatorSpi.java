//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.mozilla.jss.provider.javax.crypto;

import java.security.PublicKey;
import javax.crypto.KEM;
import javax.crypto.KEMSpi.EncapsulatorSpi;
import org.mozilla.jss.crypto.KEMAlgorithm;
import org.mozilla.jss.pkcs11.PK11Exception;
import org.mozilla.jss.pkcs11.PKCS11Constants;

/**
 *
 */
public class JSSKEMEncapsulatorSpi implements EncapsulatorSpi {

    private final KEMAlgorithm kem;
    private final PublicKey publicKey;

    public JSSKEMEncapsulatorSpi(PublicKey publicKey, KEMAlgorithm kem) {
        this.kem = kem;
        this.publicKey = publicKey;
    }

    @Override
    public KEM.Encapsulated engineEncapsulate(int from, int to, String algorithm) {
        if (from < 0 || from > to) {
            throw new UnsupportedOperationException("Encapsulate range invalid");
        }
        long alg = switch(algorithm) {
            case "AES-CBC" -> PKCS11Constants.CKM_AES_CBC;
            case "AES-ECB" -> PKCS11Constants.CKM_AES_ECB;
            case "AES-GCM" -> PKCS11Constants.CKM_AES_GCM;
            case "DERIVE" -> PKCS11Constants.CKM_HKDF_DERIVE;
            case "Generic" -> PKCS11Constants.CKM_GENERIC_SECRET_KEY_GEN;
            default -> throw new UnsupportedOperationException("Encapsulate algorithm not supported: " + algorithm);
        };
        return engineEncapsulateNative(publicKey, (to-from), alg);
    }

    @Override
    public int engineSecretSize() {
        if (kem != null)
            return kem.getSecretSize();
        throw new PK11Exception("KEM algorithm not provided");
    }

    @Override
    public int engineEncapsulationSize() {
        if (kem != null)
            return kem.getCipherSize();
        throw new PK11Exception("KEM algorithm not provided");
    }

    private native KEM.Encapsulated engineEncapsulateNative(PublicKey publicKey, int size, long algorithm);
}
