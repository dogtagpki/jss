/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkcs11;

import org.mozilla.jss.util.NativeProxy;

final class CipherContextProxy extends NativeProxy {
    public CipherContextProxy(byte[] pointer) {
        super(pointer);
    }

    @Override
    protected native void releaseNativeResources();

    @Override
    protected void finalize() throws Throwable {
      super.finalize();
    }
}
