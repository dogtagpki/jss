/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.crypto;

import java.security.spec.AlgorithmParameterSpec;

/**
 * An algorithm parameter that consists of an initialization vector (IV).
 */
public class IVParameterSpec implements AlgorithmParameterSpec {

    private byte[] iv;

    private IVParameterSpec() { }

    public IVParameterSpec(byte[] iv) {
        this.iv = iv;
    }

    /**
     * Returns a reference to an internal copy of the initialization vector.
     */
    public byte[] getIV() {
        return iv;
    }
}
