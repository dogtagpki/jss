/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.crypto;

/**
 * This exception is thrown if an initialization operation
 * is attempted on something that is already initialized.
 */
public class AlreadyInitializedException extends java.lang.Exception {
    private static final long serialVersionUID = 1L;
    public AlreadyInitializedException() {}
    public AlreadyInitializedException(String mesg) {
        super(mesg);
    }
}
