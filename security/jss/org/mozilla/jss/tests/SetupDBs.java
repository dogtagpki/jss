/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.tests;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.*;
import org.mozilla.jss.util.*;

/**
* Create the NSS databases 
*
**/

public class SetupDBs {

    public static void main(String args[]) {
      try {
        if( args.length != 2 ) {
            System.err.println("Usage: java org.mozilla.jss.tests.SetupDBs " +
			       "<dbdir> <passwordFile>\n" + 
                               "Password file should have format:\n " +
                               "Internal\\ Key\\ Storage\\ Token=m1oZilla\n " +
                               "NSS\\ FIPS\\ 140-2\\ User\\ Private\\ " +
                               "Key=m1oZilla\n");
            System.exit(1);
        }
        String dbdir = args[0];
        
        CryptoManager.initialize(dbdir);
        CryptoManager cm = CryptoManager.getInstance();

        CryptoToken tok = cm.getInternalKeyStorageToken();
        tok.initPassword( new NullPasswordCallback(),
            new FilePasswordCallback( args[1] )
        );
        
        Thread.currentThread().sleep(3*1000);
        
        System.exit(0);
      } catch(Exception e) {
        e.printStackTrace();
        System.exit(1);
      }
    }

}
