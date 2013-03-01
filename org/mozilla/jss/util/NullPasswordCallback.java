/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.util;

/**
 * A PasswordCallback that immediately gives up.  This should be used
 * when a user is not available to enter a password.  Any operations
 * that require a password will fail if this is used, unless the token
 * has already been logged in manually.
 *
 * @see org.mozilla.jss.crypto.CryptoToken#login
 */
public class NullPasswordCallback implements PasswordCallback {

    public Password getPasswordFirstAttempt(PasswordCallbackInfo info) 
        throws PasswordCallback.GiveUpException
    {
        throw new PasswordCallback.GiveUpException();
    }

    public Password getPasswordAgain(PasswordCallbackInfo info)
        throws PasswordCallback.GiveUpException
    {
        throw new PasswordCallback.GiveUpException();
    }
}
