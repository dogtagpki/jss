/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss;

/**
 * This exception is thrown if the certificate database does not exist,
 * or if an error occurs while opening it.
 */
public class CertDatabaseException extends java.lang.Exception {
    public CertDatabaseException() {}
    public CertDatabaseException(String mesg) {
        super(mesg);
    }
}
