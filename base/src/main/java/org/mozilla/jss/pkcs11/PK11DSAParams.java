//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.mozilla.jss.pkcs11;

import java.math.BigInteger;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAParameterSpec;

/**
 * Common interface for DSA Parameter spec
 * 
 * DSAParams and AlgorithmParameterSpec are not related making impossible to
 * create a common getParams method for all private keys. This class can be
 * used as DSAParams to make methods compatible.
 * 
 * This was already fixed in Java 22.
 * 
 * @see <a href="https://bugs.openjdk.org/browse/JDK-8318108">JDK-8318108</a>
 */
public class PK11DSAParams extends DSAParameterSpec implements AlgorithmParameterSpec {
    
    public PK11DSAParams(BigInteger p, BigInteger q, BigInteger g) {
        super(p, q, g);
    }
    
}
