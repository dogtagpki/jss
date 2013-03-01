/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

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
