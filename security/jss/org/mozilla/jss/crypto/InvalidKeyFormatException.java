/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.crypto;

/**
 * An exception of this type is thrown if an encoded private key
 * cannot be decoded.
 */
public class InvalidKeyFormatException
        extends java.security.spec.InvalidKeySpecException
{
    public InvalidKeyFormatException() {
        super();
    }
    public InvalidKeyFormatException(String mesg) {
        super(mesg);
    }
}
