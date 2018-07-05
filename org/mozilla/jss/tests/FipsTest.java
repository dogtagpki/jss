/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.tests;

import java.util.Enumeration;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.InitializationValues;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.pkcs11.PK11Module;
import org.mozilla.jss.pkcs11.PK11Token;
import org.mozilla.jss.util.PasswordCallback;


public class FipsTest {

    public static void main(String args[]) {

      try {

        if( args.length < 2 ) {
            System.out.println("Usage: FipsTest <dbdir> <fipsmode enter: " +
                    "enable OR disable OR chkfips > <password file>");
            return;
        }
        String dbdir = args[0];
        String fipsmode = args[1];

        String password = "";

        if (args.length == 3) {
           password = args[2];
           System.out.println("The password file " +password);
        }

        InitializationValues vals = new
                InitializationValues(dbdir);

        System.out.println("output of Initilization values ");
        System.out.println("Manufacturer ID: " + vals.getManufacturerID());
        System.out.println("Library: " + vals.getLibraryDescription());
        System.out.println("Internal Slot: " +
                            vals.getInternalSlotDescription());
        System.out.println("Internal Token: " +
                            vals.getInternalTokenDescription());
        System.out.println("Key Storage Slot: "  +
                            vals.getFIPSKeyStorageSlotDescription());
        System.out.println("Key Storage Token: "  +
                            vals.getInternalKeyStorageTokenDescription());
        System.out.println("FIPS Slot: " +
                            vals.getFIPSSlotDescription());
        System.out.println("FIPS Key Storage: " +
                            vals.getFIPSKeyStorageSlotDescription());


        if (fipsmode.equalsIgnoreCase("enable")) {
            vals.fipsMode = InitializationValues.FIPSMode.ENABLED;
        } else if (fipsmode.equalsIgnoreCase("disable")){
            vals.fipsMode =
                    InitializationValues.FIPSMode.DISABLED;
        } else {
            vals.fipsMode =
                    InitializationValues.FIPSMode.UNCHANGED;
        }

        CryptoManager.initialize(vals);

        CryptoManager cm = CryptoManager.getInstance();

        if (cm.FIPSEnabled() == true ) {
            System.out.println("\n\t\tFIPS enabled\n");
        } else {
            System.out.println("\n\t\tFIPS not enabled\n");
        }


        Enumeration<PK11Module> modules = cm.getModules();
        System.out.println("\nListing of Modules:");
        while (modules.hasMoreElements()) {
            System.out.println("\t"+
            modules.nextElement().getName() );
        }
        CryptoToken tok;
        String tokenName;

        Enumeration<CryptoToken> tokens = cm.getAllTokens();
        System.out.println("\nAll Tokens:");
        while (tokens.hasMoreElements()) {
            tok = tokens.nextElement();

            System.out.print("\t" + tok.getName());
            if (tok.needsLogin() == true){
                System.out.println("\t - Needs login.\n");
            } else {
                System.out.println("\t - Does not need login.\n");
            }
        }

        tokens = cm.getExternalTokens();
        System.out.println("\nExternal Tokens:");
        while(tokens.hasMoreElements()) {
            System.out.println("\t"+
            tokens.nextElement().getName() );
        }

        /* find the Internal Key Storage token */
        if (cm.FIPSEnabled() == true ) {
            tokenName = vals.getFIPSSlotDescription();
        } else {
            tokenName = vals.getInternalKeyStorageTokenDescription();
        }

        /* truncate to 32 bytes and remove trailing white space*/
        tokenName = tokenName.substring(0, 32);
        tokenName = tokenName.trim();
        System.out.println("\nFinding the Internal Key Storage token: "+
                tokenName);
        tok = cm.getTokenByName(tokenName);

        if( ((PK11Token)tok).isInternalKeyStorageToken()
                && tok.equals(cm.getInternalKeyStorageToken()) ) {
            System.out.println("Good, "+tok.getName()+", knows it is " +
                    "the internal Key Storage Token");
        } else {
            System.out.println("ERROR: "+tok.getName()+", doesn't know"+
                " it is the internal key storage token");
        }

        if (!password.equals("")) {
           System.out.println("logging in to the Token: " + tok.getName());
           PasswordCallback cb = new FilePasswordCallback(password);
           tok.login(cb);
           System.out.println("logged in to the Token: " + tok.getName());
        }

        /* find the Internal Crypto token */
        if (cm.FIPSEnabled() == true ) {
            tokenName = vals.getFIPSSlotDescription();
        } else {
            tokenName =  vals.getInternalTokenDescription();
        }

        /* truncate to 32 bytes and remove trailing white space*/
        tokenName = tokenName.substring(0, 32);
        tokenName = tokenName.trim();
        System.out.println("\nFinding the Internal Crypto token: " + tokenName);
        tok = cm.getTokenByName(tokenName);

        if( ((PK11Token)tok).isInternalCryptoToken() &&
                        tok.equals(cm.getInternalCryptoToken() )) {
            System.out.println("Good, "+tok.getName()+
                    ", knows it is the internal Crypto token");
        } else {
            System.out.println("ERROR: "+tok.getName()+
                ", doesn't know that it is the internal Crypto token");
        }

        System.exit(0);

      } catch( Exception e ) {
        e.printStackTrace();
        System.exit(1);
      }
    }
}
