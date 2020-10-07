/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss.crypto;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.math.BigInteger;

/**
 * This class specifies the parameters used for generating an RSA key pair.
 */
public class RSAParameterSpec extends RSAKeyGenParameterSpec {

    /**
     * Creates a new RSAParameterSpec with the specified parameter values.
     * @param keySize The size of the modulus in bits.
     * @param publicExponent The public exponent <i>e</i>.  Common values
     *      are 3, 17, and 65537.  65537 is recommended.
     */
    public RSAParameterSpec(int keySize, BigInteger publicExponent) {
        super(keySize, publicExponent);
    }

    /**
     * Returns the size of the modulus in bits.
     */
    public int getKeySize() { return getKeysize(); }
}
