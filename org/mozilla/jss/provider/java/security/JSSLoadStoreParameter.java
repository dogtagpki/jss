/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.provider.java.security;

import java.security.KeyStore.LoadStoreParameter;
import java.security.KeyStore.ProtectionParameter;

import org.mozilla.jss.crypto.CryptoToken;

public class JSSLoadStoreParameter implements LoadStoreParameter {

    CryptoToken token;

    public JSSLoadStoreParameter(CryptoToken token) {
        this.token = token;
    }

    @Override
    public ProtectionParameter getProtectionParameter() {
        return null;
    }

    public CryptoToken getToken() {
        return token;
    }
}
