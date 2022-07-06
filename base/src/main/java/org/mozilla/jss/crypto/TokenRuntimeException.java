/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss.crypto;

/**
 * This class indicates that an unknown error occurred on a CryptoToken.
 * The nature of CryptoTokens makes such unpredictable errors possible.
 * For example, a smartcard could be yanked out of its slot in the middle
 * of a cryptographic operation.
 */
public class TokenRuntimeException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public TokenRuntimeException() { super(); }

    public TokenRuntimeException(String mesg) {
        super(mesg);
    }

    public TokenRuntimeException(String mesg, Throwable cause) {
        super(mesg, cause);
    }

    public TokenRuntimeException(String mesg, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(mesg, cause, enableSuppression, writableStackTrace);
    }
}
