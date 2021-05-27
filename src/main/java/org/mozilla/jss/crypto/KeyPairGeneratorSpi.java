/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.crypto;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import org.mozilla.jss.pkcs11.PKCS11Constants;

public abstract class KeyPairGeneratorSpi {

    public KeyPairGeneratorSpi() {
    }

    public abstract void initialize(int strength, SecureRandom random);

    public abstract void initialize(AlgorithmParameterSpec params,
            SecureRandom random)
            throws InvalidAlgorithmParameterException;

    public abstract KeyPair generateKeyPair() throws TokenException;

    public abstract int getCurveCodeByName(String curveName) throws InvalidParameterException;

    public abstract void temporaryPairs(boolean temp);

    public abstract void sensitivePairs(boolean sensitive);

    public abstract void extractablePairs(boolean extractable);

    public abstract boolean keygenOnInternalToken();

    /**
     * In PKCS #11, each keypair can be marked with the operations it will
     * be used to perform. Some tokens require that a key be marked for
     * an operation before the key can be used to perform that operation;
     * other tokens don't care. NSS provides a way to specify a set of
     * flags and a corresponding mask for these flags. If a specific usage
     * is desired set the value for that usage. If it is not set, let NSS
     * behave in it's default fashion. If a behavior is desired, also set
     * that behavior in the mask as well as the flags.
     *
     */
    public enum Usage {

        ENCRYPT(PKCS11Constants.CKF_ENCRYPT), DECRYPT(PKCS11Constants.CKF_DECRYPT), SIGN(
                PKCS11Constants.CKF_SIGN), SIGN_RECOVER(PKCS11Constants.CKF_SIGN_RECOVER), VERIFY(
                        PKCS11Constants.CKF_VERIFY), VERIFY_RECOVER(PKCS11Constants.CKF_VERIFY_RECOVER), WRAP(
                                PKCS11Constants.CKF_WRAP), UNWRAP(
                                        PKCS11Constants.CKF_UNWRAP), DERIVE(PKCS11Constants.CKF_DERIVE);

        private final long value;

        Usage(long value) {
            this.value = value;
        }

        /**
         * @deprecated Use <code>ordinal()</code> instead.
         */
        @Deprecated
        public int getVal() {
            return ordinal();
        }

        /**
         * Get PKCS #11 CKF_ value.
         */
        public long value() {
            return value;
        }
    }

    /**
     * setKeyPairUsages
     * 
     * @param usages Usages.
     * @param usages_mask Usages mask.
     */
    public abstract void setKeyPairUsages(KeyPairGeneratorSpi.Usage[] usages,
            KeyPairGeneratorSpi.Usage[] usages_mask);
}
