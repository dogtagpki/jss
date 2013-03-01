/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.tests;

import java.security.*;
import java.io.*;
import org.mozilla.jss.util.*;
import org.mozilla.jss.*;


public class JCASigTest {

    public static void usage() {
        System.out.println(
        "Usage: java org.mozilla.jss.tests.JCASigTest <dbdir> <passwordFile>");
    }

    public static void sigTest(String alg, KeyPair keyPair) {
        byte[] data = new byte[] {1,2,3,4,5,6,7,8,9};
        byte[] signature;
        Signature signer;

        try {
            signer = Signature.getInstance(alg);

            System.out.println("Created a signing context");
            Provider provider = signer.getProvider();
            System.out.println("The provider used for the signer " 
                 + provider.getName() + " and the algorithm was " + alg);
            if (provider.getName().equalsIgnoreCase("Mozilla-JSS") == false) {
                System.out.println("Mozilla-JSS is supposed to be the " +
                    "default provider for JCASigTest");
                System.exit(1);
            }

            signer.initSign(
                   (org.mozilla.jss.crypto.PrivateKey)keyPair.getPrivate());
            System.out.println("initialized the signing operation");

            signer.update(data);
            System.out.println("updated signature with data");
            signature = signer.sign();
            System.out.println("Successfully signed!");

            signer.initVerify(keyPair.getPublic());
            System.out.println("initialized verification");
            signer.update(data);
            System.out.println("updated verification with data");
            if ( signer.verify(signature) ) {
                System.out.println("Signature Verified Successfully!");
            } else {
                System.out.println("ERROR: Signature failed to verify.");
            }
        } catch ( Exception e ) {
            e.printStackTrace();
            System.exit(1);
        }
    }

    public static void main(String args[]) {
        CryptoManager manager;
        KeyPairGenerator kpgen;
        KeyPair keyPair;

        if ( args.length != 2 ) {
            usage();
            System.exit(1);
        }
        String dbdir = args[0];
        String file = args[1];
        try {
            CryptoManager.InitializationValues vals = new
                                CryptoManager.InitializationValues (dbdir );
            vals.removeSunProvider = true;
            CryptoManager.initialize(vals);
            manager = CryptoManager.getInstance();
            manager.setPasswordCallback( new FilePasswordCallback(file) );

            Debug.setLevel(Debug.OBNOXIOUS);
            Provider[] providers = Security.getProviders();
            for ( int i=0; i < providers.length; i++ ) {
                System.out.println("Provider "+i+": "+providers[i].getName());
            }

            // Generate an RSA keypair
            kpgen = KeyPairGenerator.getInstance("RSA");
            kpgen.initialize(1024);
            keyPair = kpgen.generateKeyPair();
            Provider  provider = kpgen.getProvider();

            System.out.println("The provider used to Generate the Keys was " 
                                + provider.getName() );
            System.out.println("provider info " + provider.getInfo() );
            
            if (provider.getName().equalsIgnoreCase("Mozilla-JSS") == false) {
                System.out.println("Mozilla-JSS is supposed to be the " +
                    "default provider for JCASigTest");
                System.exit(1);
            }

            sigTest("MD5/RSA", keyPair);
            sigTest("MD2/RSA", keyPair);
            sigTest("SHA-1/RSA", keyPair);
            sigTest("SHA-256/RSA", keyPair);
            sigTest("SHA-384/RSA", keyPair);
            sigTest("SHA-512/RSA", keyPair);

            // Generate an DSA keypair
            kpgen = KeyPairGenerator.getInstance("DSA");
            kpgen.initialize(1024);
            keyPair = kpgen.generateKeyPair();
            provider = kpgen.getProvider();

            System.out.println("The provider used to Generate the Keys was " 
                                + provider.getName() );
            System.out.println("provider info " + provider.getInfo() );
            
            if (provider.getName().equalsIgnoreCase("Mozilla-JSS") == false) {
                System.out.println("Mozilla-JSS is supposed to be the " +
                    "default provider for JCASigTest");
                System.exit(1);
            }

            sigTest("SHA-1/DSA", keyPair);

            kpgen = KeyPairGenerator.getInstance("EC");
            kpgen.initialize(256);
            keyPair = kpgen.generateKeyPair();
            provider = kpgen.getProvider();

            System.out.println("The provider used to Generate the Keys was " 
                                + provider.getName() );
            System.out.println("provider info " + provider.getInfo() );
            
            if (provider.getName().equalsIgnoreCase("Mozilla-JSS") == false) {
                System.out.println("Mozilla-JSS is supposed to be the " +
                    "default provider for JCASigTest");
                System.exit(1);
            }
            sigTest("SHA-1/EC", keyPair);
            sigTest("SHA-256/EC", keyPair);
            sigTest("SHA-384/EC", keyPair);
            sigTest("SHA-512/EC", keyPair);

        } catch ( Exception e ) {
            e.printStackTrace();
	    System.exit(1);
        }
	System.exit(0);
    }
}
