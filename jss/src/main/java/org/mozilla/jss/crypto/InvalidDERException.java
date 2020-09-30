/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.crypto;

/**
 * This exception is thrown when we encounter a bogus DER blob.
 */
public class InvalidDERException extends Exception {
    private static final long serialVersionUID = 1L;
    public InvalidDERException() { super(); }
    public InvalidDERException(String mesg) { super(mesg); }
    public InvalidDERException(String mesg, Throwable cause) { super(mesg, cause); }

    public InvalidDERException(String mesg, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(mesg, cause, enableSuppression, writableStackTrace);
    }
}
