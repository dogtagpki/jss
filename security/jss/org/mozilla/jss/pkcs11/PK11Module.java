/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss.pkcs11;

import org.mozilla.jss.util.Assert;
import java.util.Enumeration;
import java.util.Vector;

public final class PK11Module {

    private PK11Module() {
        Assert.notReached("PK11Module default constructor");
    }

    /**
     * This constructor should only be called from native code.
     */
    private PK11Module(byte[] pointer) {
        Assert._assert(pointer!=null);
        moduleProxy = new ModuleProxy(pointer);
        reloadTokens();
    }

    /**
     * Returns the common name of this module.
     */
    public native String getName();

    /**
     * Returns the name of the shared library implementing this module.
     */
    public native String getLibraryName();

    /**
     * Get the CryptoTokens provided by this module.
     *
     * @return An enumeration of CryptoTokens that come from this module.
     */
    public synchronized Enumeration getTokens() {
        return tokenVector.elements();
    }

    /**
     * Re-load the list of this module's tokens. This function is private
     * to JSS.
     */
    public synchronized void reloadTokens() {
        tokenVector = new Vector();
        putTokensInVector(tokenVector);
    }

    private native void putTokensInVector(Vector tokens);

    private Vector tokenVector;
    private ModuleProxy moduleProxy;
}
