/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss;

/**
 * Thrown if a token cannot be found.
 */
public class NoSuchTokenException extends java.lang.Exception {
    public NoSuchTokenException() {}
    public NoSuchTokenException(String mesg) {
        super(mesg);
    }
}
