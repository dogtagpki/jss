/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.asn1;

/**
 * An exception thrown when an optional field is not present.
 */
public class FieldNotPresentException extends java.lang.Exception
{
    private static final long serialVersionUID = 1L;

    public FieldNotPresentException() {
        super();
    }

    public FieldNotPresentException(String mesg) {
        super(mesg);
    }

    public FieldNotPresentException(String mesg, Throwable cause) {
        super(mesg, cause);
    }

    public FieldNotPresentException(String mesg, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(mesg, cause, enableSuppression, writableStackTrace);
    }
}
