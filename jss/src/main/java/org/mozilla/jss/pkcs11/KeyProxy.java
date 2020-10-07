/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss.pkcs11;

abstract class KeyProxy extends org.mozilla.jss.util.NativeProxy {

    protected KeyProxy(byte[] pointer) {
        super(pointer);
    }

    protected void finalize() throws Throwable {
        super.finalize();
    }
}
