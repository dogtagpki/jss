/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkcs11;

import org.mozilla.jss.util.NativeProxy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class TokenProxy extends NativeProxy {

    public static Logger logger = LoggerFactory.getLogger(TokenProxy.class);

    public TokenProxy(byte[] pointer) {
        super(pointer);
    }

    protected native void releaseNativeResources();
}
