/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.util;

/**
 * Represents a password callback, which is called to login to the key
 * database and to PKCS #11 tokens.
 * <p>The simplest implementation of a PasswordCallback is a Password object.
 * 
 * @see org.mozilla.jss.util.Password
 * @see org.mozilla.jss.util.NullPasswordCallback
 * @see org.mozilla.jss.util.ConsolePasswordCallback
 * @see org.mozilla.jss.CryptoManager#setPasswordCallback
 */
public interface PasswordCallback {

    /**
     * This exception is thrown if the <code>PasswordCallback</code>
     * wants to stop guessing passwords.
     */
    public static class GiveUpException extends Exception {
        public GiveUpException() { super(); }
        public GiveUpException(String mesg) { super(mesg); }
    }

    /**
     * Supplies a password. This is called on the first attempt; if it
     * returns the wrong password, <code>getPasswordAgain</code> will
     * be called on subsequent attempts. 
     *
	 * @param info Information about the token that is being logged into.
	 * @return The password.  This password object is owned	by and will
     *      be cleared by the caller.
     * @exception GiveUpException If the callback does not want to supply
     *  a password.
     */
	public Password getPasswordFirstAttempt(PasswordCallbackInfo info)
		throws GiveUpException;

    /**
     * Tries supplying a password again. This callback will be called if
	 * the first callback returned an invalid password.  It will be called
     * repeatedly until it returns a correct password, or it gives up by
     * throwing a <code>GiveUpException</code>.
     *
	 * @param info Information about the token that is being logged into.
	 * @return The password.  This password object is owned by and will
     *      be cleared by the caller.
     * @exception GiveUpException If the callback does not want to supply
     *  a password.  This may often be the case if the first attempt failed.
     */
    public Password getPasswordAgain(PasswordCallbackInfo info)
        throws GiveUpException;
}
