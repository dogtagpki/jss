/* ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is the Netscape Security Services for Java.
 *
 * The Initial Developer of the Original Code is
 * Netscape Communications Corporation.
 * Portions created by the Initial Developer are Copyright (C) 1998-2000
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either the GNU General Public License Version 2 or later (the "GPL"), or
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the MPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the MPL, the GPL or the LGPL.
 *
 * ***** END LICENSE BLOCK ***** */

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
