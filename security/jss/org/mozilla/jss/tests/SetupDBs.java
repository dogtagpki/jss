/* ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is the Netscape Security Services for Java.
 *
 * The Initial Developer of the Original Code is
 * Netscape Communications Corporation.
 * Portions created by the Initial Developer are Copyright (C) 2001
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either the GNU General Public License Version 2 or later (the "GPL"), or
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the MPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the MPL, the GPL or the LGPL.
 *
 * ***** END LICENSE BLOCK ***** */

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
