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
 * Portions created by the Initial Developer are Copyright (C) 1998-2000
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

import org.mozilla.jss.crypto.*;
import org.mozilla.jss.CryptoManager;
import java.util.Enumeration;
import java.math.BigInteger;
import java.security.PrivateKey;

public final class CloseDBs extends org.mozilla.jss.DatabaseCloser {

    public CloseDBs() throws Exception {
        super();
    }

    public static void main(String args[]) {
        int i;
      try {
        if(args.length != 1) {
            System.err.println("Usage: CloseDBs <dbdir>");
            System.exit(0);
        }

        CryptoManager.initialize( args[0] );

        CryptoManager manager = CryptoManager.getInstance();

        Enumeration tokens = manager.getAllTokens();
        CryptoStore store;
        X509Certificate certs[];
        java.security.PrivateKey keys[];
        while(tokens.hasMoreElements()) {
            CryptoToken token = (CryptoToken) tokens.nextElement();
            store = token.getCryptoStore();
            System.out.println("Token: "+token.getName());

            certs = store.getCertificates();
            System.out.println("Certs:");
            for(i=0; i < certs.length; i++) {
                System.out.println( certs[i].getNickname() );
            }

            keys = store.getPrivateKeys();
            System.out.println("Keys:");
            try {
                for(i=0; i < keys.length; i++) {
                    System.out.println(new BigInteger(keys[i].getEncoded()));
                }
            } catch (Exception ex) {
                System.out.println(ex.getMessage());
            }
        }

        System.out.println("Closing databases...");
        try {
            (new CloseDBs()).closeDatabases();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
            System.exit(1);
        }
        System.out.println("Databases are closed.");
        System.exit(0);
      } catch(Exception e) {
            e.printStackTrace();
            System.exit(1);
      }
    }
}
