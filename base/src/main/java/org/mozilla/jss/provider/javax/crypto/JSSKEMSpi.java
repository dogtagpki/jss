//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.mozilla.jss.provider.javax.crypto;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.KEMSpi;
import org.mozilla.jss.crypto.KEMAlgorithm;
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
        if (!isPublicKeyCompatible(publicKey))
            throw new InvalidKeyException("Incompatible key with " + kemAlgorithm.toString());
        // Currently parameter spec and random are not supported. Default are in use
        logger.debug("Creating KEM encapsulator with KEM key type " +
                (kemAlgorithm == null ? "ANY" : kemAlgorithm.toString()));
        return new JSSKEMEncapsulatorSpi(publicKey, kemAlgorithm);
    }

    @Override
    public KEMSpi.DecapsulatorSpi engineNewDecapsulator(PrivateKey privateKey, AlgorithmParameterSpec spec) throws InvalidAlgorithmParameterException, InvalidKeyException {
        if (!isPrivateKeyCompatible(privateKey))
            throw new InvalidKeyException("Incompatible key with " + kemAlgorithm.toString());
        // Currently parameter spec and random are not supported. Default are in use
        logger.debug("Creating KEM decapsulator with KEM key type " +
                (kemAlgorithm == null ? "ANY" : kemAlgorithm.toString()));
        return new JSSKEMDecapsulatorSpi(privateKey, kemAlgorithm);
    }
    

    private boolean isPublicKeyCompatible(PublicKey publicKey) {
        //TODO: this has to be implemented
        return true;
    }
    
    private boolean isPrivateKeyCompatible(PrivateKey privateKey) {
        //TODO: this has to be implemented
        return true;
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
