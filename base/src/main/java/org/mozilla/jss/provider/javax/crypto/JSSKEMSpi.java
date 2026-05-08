//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.mozilla.jss.provider.javax.crypto;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.KEMSpi;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.crypto.KEMAlgorithm;
import org.mozilla.jss.pkcs11.KeyType;
import org.mozilla.jss.pkcs11.PK11PrivKey;
import org.mozilla.jss.pkcs11.PK11PubKey;
import org.mozilla.jss.pkix.primitive.SubjectPublicKeyInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 */
public class JSSKEMSpi implements KEMSpi{

    private static final Logger logger = LoggerFactory.getLogger(JSSKEMSpi.class);
    private KEMAlgorithm kemAlgorithm = null;

    public JSSKEMSpi() {
    }

    public JSSKEMSpi(KEMAlgorithm kemAlg) {
        this.kemAlgorithm = kemAlg;
    }    

    @Override
    public KEMSpi.EncapsulatorSpi engineNewEncapsulator(PublicKey publicKey, AlgorithmParameterSpec spec, SecureRandom secureRandom) throws InvalidAlgorithmParameterException, InvalidKeyException {
        if (spec != null) {
            throw new InvalidAlgorithmParameterException("JSSKEMSpi: AlgorithmParameterSpec not supported");
        }
        if (!isPublicKeyCompatible(publicKey))
            throw new InvalidKeyException("Incompatible key with " + 
                    (kemAlgorithm == null ? "ML-KEM" : kemAlgorithm.toString()));
        // Currently parameter spec and random are not supported. Default are in use
        logger.debug("JSSKEMSpi: Creating KEM encapsulator with KEM key type " +
                (kemAlgorithm == null ? "ML-KEM" : kemAlgorithm.toString()));
        return new JSSKEMEncapsulatorSpi(publicKey, kemAlgorithm);
    }

    @Override
    public KEMSpi.DecapsulatorSpi engineNewDecapsulator(PrivateKey privateKey, AlgorithmParameterSpec spec) throws InvalidAlgorithmParameterException, InvalidKeyException {
        if (spec != null) {
            throw new InvalidAlgorithmParameterException("JSSKEMSpi: AlgorithmParameterSpec not supported");
        }
        if (!isPrivateKeyCompatible(privateKey))
            throw new InvalidKeyException("Incompatible key with " +
                    (kemAlgorithm == null ? "ML-KEM" : kemAlgorithm.toString()));
        // Currently parameter spec and random are not supported. Default are in use
        logger.debug("JSSKEMSpi: Creating KEM decapsulator with KEM key type " +
                (kemAlgorithm == null ? "ML-KEM" : kemAlgorithm.toString()));
        return new JSSKEMDecapsulatorSpi(privateKey, kemAlgorithm);
    }
    

    private boolean isPublicKeyCompatible(PublicKey publicKey) {
        if(!(publicKey instanceof PK11PubKey)) {
            return false;
        }
        SubjectPublicKeyInfo spk;
        try {
            spk = new SubjectPublicKeyInfo(publicKey);
        } catch (InvalidBERException ex) {
            logger.error("JSSKEMSpi: public key not valid.");
            return false;
        }
        
        if(kemAlgorithm == null) {
            try {
                KEMAlgorithm.fromOID(spk.getAlgorithmIdentifier().getOID());
                return true;
            } catch (NoSuchAlgorithmException ex) {
                logger.error("JSSKEMSpi: key algorithm not supported.");
                return false;
            }
        }
        if (kemAlgorithm.toString().equals(spk.getAlgorithm())) {
            return true;
        }
        return false;
    }
    
    private boolean isPrivateKeyCompatible(PrivateKey privateKey) {
        if(privateKey instanceof PK11PrivKey pKey) {
            if (pKey.getKeyType() != KeyType.MLKEM){
                return false;
            }
            if(kemAlgorithm == null) {
                try {
                    KEMAlgorithm.fromOID(pKey.getType().toOID());
                    return true;
                } catch (NoSuchAlgorithmException ex) {
                    logger.error("JSSKEMSpi: key algorithm not supported.");
                    return false;
                }
            }
            if(kemAlgorithm.toString().equals(pKey.getAlgorithm())) {
                return true;
            }
        }
        return false;
    }

    public static class MLKEM extends JSSKEMSpi {
        public MLKEM() {
            super();
        }
    }
    public static class MLKEM512 extends JSSKEMSpi {
        public MLKEM512() {
            super(KEMAlgorithm.MLKEM512);
        }
    }
    public static class MLKEM768 extends JSSKEMSpi {
        public MLKEM768() {
            super(KEMAlgorithm.MLKEM768);
        }
    }
    public static class MLKEM1024 extends JSSKEMSpi {
        public MLKEM1024() {
            super(KEMAlgorithm.MLKEM1024);
        }
    }
}
