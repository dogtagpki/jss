/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.util;

/**
 * A class to allow friendly functions access to other parts of JSS.
 */
public class Tunnel {

    protected static byte[]
    GetPasswordByteCopy(Password pw) {
        return pw.getByteCopy();
    }
}
