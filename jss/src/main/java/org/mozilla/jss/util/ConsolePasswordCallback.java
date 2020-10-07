/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.util;

/**
 * A password callback that obtains its password from the console.
 * Asterisks are echoed at the prompt.
 */
public class ConsolePasswordCallback implements PasswordCallback {
    public ConsolePasswordCallback() {}
    public Password getPasswordFirstAttempt(PasswordCallbackInfo info)
        throws PasswordCallback.GiveUpException
    {
        System.out.println("Enter password for "+info.getName());
        return Password.readPasswordFromConsole();
    }

    public Password getPasswordAgain(PasswordCallbackInfo token)
        throws PasswordCallback.GiveUpException
    {
        System.out.println("Password incorrect, try again");
        return getPasswordFirstAttempt(token);
    }
}
