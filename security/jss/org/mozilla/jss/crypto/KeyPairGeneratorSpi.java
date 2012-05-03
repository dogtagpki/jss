/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.crypto;

import java.security.*;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public abstract class KeyPairGeneratorSpi {

    public KeyPairGeneratorSpi() {
    }

    public abstract void initialize(int strength, SecureRandom random);

    public abstract void initialize(AlgorithmParameterSpec params,
                                    SecureRandom random)
        throws InvalidAlgorithmParameterException;

    public abstract KeyPair generateKeyPair() throws TokenException;

    public abstract void temporaryPairs(boolean temp);

    public abstract void sensitivePairs(boolean sensitive);

    public abstract void extractablePairs(boolean extractable);

    public abstract boolean keygenOnInternalToken();

    /**
     * In PKCS #11, each keypair can be marked with the operations it will
     * be used to perform. Some tokens require that a key be marked for
     * an operation before the key can be used to perform that operation;
     * other tokens don't care. NSS provides a way to specify a set of
     * flags and a corresponding mask for these flags.  If a specific usage
     * is desired set the value for that usage. If it is not set, let NSS
     * behave in it's default fashion.  If a behavior is desired, also set
     * that behavior in the mask as well as the flags.
     * 
     */
    public final static class Usage {
        private Usage() { }
        private Usage(int val) { this.val = val;}
        private int val;

        public int getVal() { return val; }

        // these enums must match the 
        // opFlagForUsage listed in PK11KeyPairGenerator.java
        public static final Usage ENCRYPT = new Usage(0);
        public static final Usage DECRYPT = new Usage(1);
        public static final Usage SIGN = new Usage(2);
        public static final Usage SIGN_RECOVER = new Usage(3);
        public static final Usage VERIFY = new Usage(4);
        public static final Usage VERIFY_RECOVER = new Usage(5);
        public static final Usage WRAP = new Usage(6);
        public static final Usage UNWRAP = new Usage(7);
        public static final Usage DERIVE = new Usage(8);
    }

    /**
     * setKeyPairUsages
     * @param usages
     * @param usages_mask
     */
    public abstract void setKeyPairUsages(KeyPairGeneratorSpi.Usage[] usages,
                                          KeyPairGeneratorSpi.Usage[] usages_mask);
}
