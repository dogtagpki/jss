/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss.crypto;

/**
 * The org.mozilla.jss.provider package comes before CryptoManager in
 * the dependency list, so this class is used to allow them to access
 * CryptoManager sneakily.  When CryptoManager initializes, it registers
 * itself as a token supplier with <code>setTokenSupplier</code>.  Then
 * the providers call <code>getTokenSupplier</code> when they need to use
 * CryptoManager.  CryptoManager implements the TokenSupplier interface.
 */
public class TokenSupplierManager {
    static private TokenSupplier supplier;
    static public void setTokenSupplier(TokenSupplier ts) {
        supplier = ts;
    }
    static public TokenSupplier getTokenSupplier() {
        return supplier;
    }
}
