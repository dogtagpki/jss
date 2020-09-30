/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.tests;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

import org.mozilla.jss.util.Password;
import org.mozilla.jss.util.PasswordCallback;
import org.mozilla.jss.util.PasswordCallbackInfo;

/**
 */
public class FilePasswordCallback implements PasswordCallback {

    private Properties passwords;

    public FilePasswordCallback(String filename) throws IOException {
        passwords = new Properties();
        try (FileInputStream in = new FileInputStream(filename)) {
            passwords.load(in);
        }
    }

    /**
     */
	public Password getPasswordFirstAttempt(PasswordCallbackInfo info)
		throws PasswordCallback.GiveUpException
    {
        String pw = passwords.getProperty(info.getName());
        if( pw == null ) {
            throw new PasswordCallback.GiveUpException();
        } else {
            System.out.println("***FilePasswordCallback returns " + pw);
            return new Password(pw.toCharArray());
        }
    }

    /**
     */
    public Password getPasswordAgain(PasswordCallbackInfo info)
        throws PasswordCallback.GiveUpException
    {
        throw new PasswordCallback.GiveUpException();
    }
}
