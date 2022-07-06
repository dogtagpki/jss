/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss.util;

/**
 * Assertion exceptions are thrown when assertion code is invoked
 * and fails to operate properly. They subclass Error, so they will
 * not be caught by exception handlers. Instead, they will cause the
 * VM to halt and print a stack trace.
 *
 * @see org.mozilla.jss.util.Assert
 * @version $Revision$ $Date$
 */
public class AssertionException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public AssertionException() {}

    public AssertionException(String mesg) {
        super(mesg);
    }

    public AssertionException(String mesg, Throwable cause) {
        super(mesg, cause);
    }

    public AssertionException(String mesg, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(mesg, cause, enableSuppression, writableStackTrace);
    }
}
