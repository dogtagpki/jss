/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.crypto;

/**
 * This exception is thrown if the user tries to import a
 * key which is already in the specified token
 */
public class KeyAlreadyImportedException extends java.lang.Exception {
    public KeyAlreadyImportedException() {}
    public KeyAlreadyImportedException(String mesg) {
        super(mesg);
    }
}
