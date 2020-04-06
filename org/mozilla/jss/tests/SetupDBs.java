/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.tests;

import org.mozilla.jss.*;
import org.mozilla.jss.crypto.*;
import org.mozilla.jss.util.*;

/**
* Create the NSS databases 
*
**/

public class SetupDBs {

    public static void main(String args[]) throws Exception {
        if (args.length != 2) {
            System.err.println("Usage: java org.mozilla.jss.tests.SetupDBs " +
			       "<dbdir> <passwordFile>\n" + 
                               "Password file should have format:\n " +
                               "Internal\\ Key\\ Storage\\ Token=m1oZilla\n " +
                               "NSS\\ FIPS\\ 140-2\\ User\\ Private\\ " +
                               "Key=m1oZilla\n");
            System.exit(1);
        }

        // Initialize JSS, preferring the local CryptoManager initialization
        // over the one from java.security.
        InitializationValues ivs = new InitializationValues(args[0]);
        CryptoManager.initialize(ivs);
        CryptoManager cm = CryptoManager.getInstance();

        // Get the internal key storage token so we can set the password.
        CryptoToken tok = cm.getInternalKeyStorageToken();

        // Set the user password to the one from the password file; the
        // security officer password is empty.
        PasswordCallback securityOfficerPassword = new NullPasswordCallback();
        PasswordCallback userPassword = new FilePasswordCallback(args[1]);
        tok.initPassword(securityOfficerPassword, userPassword);

        cm.shutdown();
    }
}
