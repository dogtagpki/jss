/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.crypto;

/**
 * Thrown if a cryptographic item does not exist on the token it is
 * trying to be used on.
 */
public class NoSuchItemOnTokenException extends Exception {

    public
    NoSuchItemOnTokenException() {}

    public
    NoSuchItemOnTokenException( String message ) {
        super( message );
    }
}
