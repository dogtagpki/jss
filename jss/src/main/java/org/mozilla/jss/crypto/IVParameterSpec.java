/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.crypto;

import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.spec.IvParameterSpec;

/**
 * An algorithm parameter that consists of an initialization vector (IV).
 */
public class IVParameterSpec extends IvParameterSpec {
    public IVParameterSpec(byte[] iv) {
        super(iv);
    }

    public IVParameterSpec(byte[] iv, int offset, int len) {
        super(iv, offset, len);
    }
}
