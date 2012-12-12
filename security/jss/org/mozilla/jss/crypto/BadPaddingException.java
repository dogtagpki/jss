/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss.crypto;

/**
 * @deprecated Use javax.crypto.BadPaddingException.
 */
public class BadPaddingException extends Exception {
    public BadPaddingException() {
        super();
    }
    public BadPaddingException(String msg) {
        super(msg);
    }
}
