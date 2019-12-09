/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss;

/**
 * Thrown if a CRL cannot be imported
 */
public class CRLImportException extends java.lang.Exception {
    private static final long serialVersionUID = 1L;
    public CRLImportException() {}

    public CRLImportException(String mesg) {
        super(mesg);
    }

    public CRLImportException(String mesg, Throwable cause) {
        super(mesg, cause);
    }

    public CRLImportException(String mesg, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(mesg, cause, enableSuppression, writableStackTrace);
    }
}
