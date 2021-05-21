/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.provider.java.security;

import org.mozilla.jss.crypto.TokenSupplierManager;
import org.mozilla.jss.crypto.JSSSecureRandom;

public class JSSSecureRandomSpi extends java.security.SecureRandomSpi {

    private static final long serialVersionUID = 1L;
    JSSSecureRandom engine;

    public JSSSecureRandomSpi() {
        super();
        engine = TokenSupplierManager.getTokenSupplier().getSecureRNG();
    }

    @Override
    protected byte[]
    engineGenerateSeed(int numBytes) {
        byte[] bytes = new byte[numBytes];
        engine.nextBytes(bytes);
        return bytes;
    }

    @Override
    protected void
    engineNextBytes(byte[] bytes) {
        engine.nextBytes(bytes);
    }

    @Override
    protected void
    engineSetSeed(byte[] seed) {
        engine.setSeed(seed);
    }
}
