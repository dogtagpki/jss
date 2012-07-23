/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkcs11;

import org.mozilla.jss.util.NativeProxy;
import org.mozilla.jss.util.Debug;

public final class TokenProxy extends NativeProxy {
        public TokenProxy(byte[] pointer) {
            super(pointer);
        }
        protected native void releaseNativeResources();
        protected void finalize() throws Throwable {
	        Debug.trace(Debug.OBNOXIOUS, "Finalizing a TokenProxy");
            super.finalize();
        }
    }
