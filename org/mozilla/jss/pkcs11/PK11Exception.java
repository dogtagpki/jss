/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkcs11;

/**
 * This is a generic PKCS #11 exception.
 */
public class PK11Exception extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public PK11Exception() {
    }

    public PK11Exception(String mesg) {
        super(mesg);
    }

    public PK11Exception(Throwable cause) {
        super(cause);
    }

    public PK11Exception(String mesg, Throwable cause) {
        super(mesg, cause);
    }

    public PK11Exception(String mesg, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(mesg, cause, enableSuppression, writableStackTrace);
    }
}
