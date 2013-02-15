/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss.crypto;

/**
 * An interface that allows providers to access CryptoManager without actually
 * knowing about CryptoManager. This is necessary to prevent cyclic
 * dependencies. CryptoManager knows about the providers, so the providers
 * can't know about CryptoManager.  Instead, CryptoManager implements
 * this interface.
 */
public interface TokenSupplier {
    public CryptoToken getInternalCryptoToken();
    public JSSSecureRandom getSecureRNG();

    public CryptoToken getThreadToken();
    public void setThreadToken(CryptoToken token);
}
