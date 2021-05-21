/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.util;

/**
 * StaticVoidPointer is a Java class that mirror a statically allocated
 * `void *` pointer in C.
 *
 * This is helpful for implementing NativeEnclosure and preventing the
 * resulting pointer from getting tracked in the usual NativeProxy allocation
 * trackers and avoiding a double free.
 */
public class StaticVoidPointer extends NativeProxy
{
    public StaticVoidPointer(byte[] pointer) {
        super(pointer, false);
    }

    @Override
    protected void releaseNativeResources() {
        /* Do nothing: this is a static pointer that doesn't need freeing. */
    }
}
