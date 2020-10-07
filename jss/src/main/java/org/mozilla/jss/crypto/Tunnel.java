/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss.crypto;

/**
 * This is a private JSS class that allows the pkcs11 package access
 * to some of the
 * package methods in the crypto package.  A friend declaration would
 * have been ideal.
 */
public class Tunnel {
    protected static Signature
    ConstructSignature( SignatureAlgorithm alg, SignatureSpi engine) {
        return new Signature(alg, engine);
    }
}

