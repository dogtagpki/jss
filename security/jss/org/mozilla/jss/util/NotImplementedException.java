/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.util;

/**
 * This exception is thrown whenever something isn't implemented.
 */
public class NotImplementedException extends Exception {
    public NotImplementedException() { super(); }
    public NotImplementedException(String mesg) { super(mesg); }
}
