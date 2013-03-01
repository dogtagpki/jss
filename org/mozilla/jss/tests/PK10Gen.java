/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.tests;

import org.mozilla.jss.crypto.*;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.pkcs11.*;
import org.mozilla.jss.pkcs11.PK11Token;
import org.mozilla.jss.util.*;

public class PK10Gen {
    public static void main(String args[]) {
		CryptoManager manager;
        Password pass1=null, pass2=null;
		char[] passchar1 = {'f', 'o', 'o', 'b', 'a', 'r'};
		char[] passchar2 = {'n', 'e', 't', 's', 'c', 'a', 'p', 'e'};

        if(args.length != 2) {
            System.err.println("Usage: java org.mozilla.jss.PK10Gen <dbdir> [rsa|dsa]");
            return;
        }

		try {
			CryptoManager.initialize(args[0]);
			/*
			CryptoManager.initialize("secmod.db", "key3.db", "cert7.db");
			CryptoManager cm = CryptoManager.getInstance();
			PK11Token token = (PK11Token)cm.getInternalCryptoToken();
			*/
			/*
        CryptoManager.InitializationValues vals = new
            CryptoManager.InitializationValues( args[0]+"/secmodule.db",
                                                args[0]+"/key3.db",
				                                args[0]+"/cert7.db");
        CryptoManager.initialize(vals);
			*/
        try {
            manager = CryptoManager.getInstance();
        } catch( CryptoManager.NotInitializedException e ) {
            System.out.println("CryptoManager not initialized");
            return;
        }

		CryptoToken token = (PK11Token) manager.getInternalKeyStorageToken();
            if(token.isLoggedIn() == false) {
                System.out.println("Good, isLoggedIn correctly says we're"+
                    " not logged in");
            } else {
                System.out.println("ERROR: isLoggedIn incorrectly says we're"+
                    " logged in");
            }

			pass1 = new Password( (char[]) passchar1.clone());
			pass2 = new Password( new char[]{0} );
            token.initPassword(pass2, pass1);
			pass1.clear();
			pass2.clear();
            System.out.println("initialized PIN");
            token.login(pass1);
            System.out.println("logged in");

			String blob = token.generateCertRequest("cn=christina Fu",
												512,
													args[1],
													(byte[]) null,
													(byte[]) null,
													(byte[]) null);
			System.out.println("pkcs#10 blob = \n" + blob);
		} catch(Exception e) {
			System.out.println("exception caught in PK10Gen: " +
							   e.getMessage());
			e.printStackTrace();
			System.exit(1);
		}
		System.exit(0);
	}
}
