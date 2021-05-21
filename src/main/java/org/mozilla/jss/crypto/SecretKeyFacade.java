/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.crypto;

public class SecretKeyFacade implements javax.crypto.SecretKey {

    private static final long serialVersionUID = 1L;
    public SymmetricKey key;

    public SecretKeyFacade(SymmetricKey symk) {
        key = symk;
    }

    @Override
    public String getAlgorithm() {
        return key.getAlgorithm();
    }

    @Override
    public byte[] getEncoded() {
        return key.getEncoded();
    }

    @Override
    public String getFormat() {
        return key.getFormat();
    }
}
