/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Note: when this program is run, it must have a key3.db WITH A PASSWORD
 * SET in the directory specified by the argument. The first time the
 * program is run, a key3.db file will be created, but it will not have
 * a password. This will result in the error:
 *  Token error: org.mozilla.jss.crypto.TokenException: unable to login to token
 *
 * To create a database with a password, you can:
 *   use the modutil or keyutil tool,
 *   use the JSS API CryptoToken.changePassword() to set the password
 *   run the test 'TokenAccessTest'
 *            which will create db with a password.
 */

package org.mozilla.jss.tests;

import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Enumeration;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.KeyPairAlgorithm;
import org.mozilla.jss.util.Base64OutputStream;

public class TestKeyGen {

    public static void main(String[] args) {
      try {
        CryptoManager manager;
        java.security.KeyPair keyPair;
        Base64OutputStream base64;

        if(args.length != 2) {
            System.err.println("Usage: java org.mozilla.jss.pkcs11." +
                               "TestKeyGen  <dbdir> <pwfile>");
            System.exit(1);
        }

        manager = CryptoManager.getInstance();
        manager.setPasswordCallback( new FilePasswordCallback(args[1]) );

        Enumeration<CryptoToken> tokens =
                manager.getTokensSupportingAlgorithm(KeyPairAlgorithm.RSA);
        System.out.println("The following tokens support RSA keygen:");
        while(tokens.hasMoreElements()) {
            System.out.println("\t"+
                tokens.nextElement().getName() );
        }

        RSAPublicKey rsaPubKey;
        RSAKeyGenParameterSpec rsaParams;

        java.security.KeyPairGenerator kpg =
            java.security.KeyPairGenerator.getInstance("RSA", "Mozilla-JSS");

        //Get rid of all the DSA keygen tests and the small keysize and exponent RSA tests.
        //This is due to evolving nss policy changes away from weaker algs.
      
        // 2048-bit RSA with default exponent
        System.out.println("Generating 2048-bit RSA KeyPair!");
        for (int cntr=0; cntr<5; cntr++ ) {
            try {
                kpg.initialize(2048);
                keyPair = kpg.genKeyPair();
                assert( keyPair.getPublic() instanceof RSAPublicKey);
                rsaPubKey = (RSAPublicKey) keyPair.getPublic();
                System.out.println("Generated 2048-bit RSA KeyPair!");
                System.out.println("Modulus: "+rsaPubKey.getModulus());
                System.out.println("Exponent: "+rsaPubKey.getPublicExponent());
                break;
            } catch (org.mozilla.jss.crypto.TokenRuntimeException TRExRSA2048) {
                if (cntr==5) {
                    System.out.println("Generation of 2048-bit RSA KeyPair Failed\n");
                    TRExRSA2048.printStackTrace();
                }
            }
        }

        // 256-bit EC
        kpg = java.security.KeyPairGenerator.getInstance("EC", "Mozilla-JSS");
        kpg.initialize(256);
        keyPair = kpg.genKeyPair();
        System.out.println("Generated 256-bit EC KeyPair!");

        kpg.initialize(384);
        keyPair = kpg.genKeyPair();
        System.out.println("Generated 384-bit EC KeyPair!");

        kpg.initialize(521);
        keyPair = kpg.genKeyPair();
        System.out.println("Generated 521-bit EC KeyPair!");

        // ML-DSA 44
        kpg = java.security.KeyPairGenerator.getInstance("ML-DSA", "Mozilla-JSS");
        kpg.initialize(44);
        keyPair = kpg.genKeyPair();
        System.out.println("Generated ML-DSA with 44!");

        kpg = java.security.KeyPairGenerator.getInstance("ML-DSA-44", "Mozilla-JSS");
        keyPair = kpg.genKeyPair();
        System.out.println("Generated ML-DSA-44!");

        // ML-DSA 65
        // It is default value
        kpg = java.security.KeyPairGenerator.getInstance("ML-DSA", "Mozilla-JSS");
        keyPair = kpg.genKeyPair();
        System.out.println("Generated ML-DSA with 65!");

        kpg = java.security.KeyPairGenerator.getInstance("ML-DSA-65", "Mozilla-JSS");
        System.out.println("Generated ML-DSA with 65!");

        // ML-DSA 87
        kpg = java.security.KeyPairGenerator.getInstance("ML-DSA", "Mozilla-JSS");
        kpg.initialize(87);
        keyPair = kpg.genKeyPair();
        System.out.println("Generated ML-DSA with 87!");

        kpg = java.security.KeyPairGenerator.getInstance("ML-DSA-87", "Mozilla-JSS");
        keyPair = kpg.genKeyPair();
        System.out.println("Generated ML-DSA-87!");

        System.out.println("TestKeyGen passed");
        System.exit(0);
      } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
      }
    }
}
