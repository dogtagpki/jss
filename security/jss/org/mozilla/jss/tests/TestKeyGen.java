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

import org.mozilla.jss.pkcs11.*;

import org.mozilla.jss.util.*;
import org.mozilla.jss.crypto.*;
import org.mozilla.jss.*;
import org.mozilla.jss.pkcs11.PK11KeyPairGenerator;
import java.io.*;
import java.awt.*;
import java.security.cert.*;
import java.security.interfaces.*;
import java.math.BigInteger;

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

        CryptoManager.initialize(args[0]);
        manager = CryptoManager.getInstance();
        manager.setPasswordCallback( new FilePasswordCallback(args[1]) );

        java.util.Enumeration tokens =
                manager.getTokensSupportingAlgorithm(KeyPairAlgorithm.RSA);
        System.out.println("The following tokens support RSA keygen:");
        while(tokens.hasMoreElements()) {
            System.out.println("\t"+
                ((CryptoToken)tokens.nextElement()).getName() );
        }
        tokens = manager.getTokensSupportingAlgorithm(KeyPairAlgorithm.DSA);
        System.out.println("The following tokens support DSA keygen:");
        while(tokens.hasMoreElements()) {
            System.out.println("\t"+
                ((CryptoToken)tokens.nextElement()).getName() );
        }

        RSAPublicKey rsaPubKey;
        DSAPublicKey dsaPubKey;
        DSAParams dsaParams;
        RSAParameterSpec rsaParams;

        java.security.KeyPairGenerator kpg =
            java.security.KeyPairGenerator.getInstance("RSA", "Mozilla-JSS");

        // 512-bit RSA with default exponent
        System.out.println("Generating 512-bit RSA KeyPair!");
        for (int cntr=0; cntr<5; cntr++ ) {
            try {
                kpg.initialize(512);
                keyPair = kpg.genKeyPair();
                Assert._assert( keyPair.getPublic() instanceof RSAPublicKey);
                rsaPubKey = (RSAPublicKey) keyPair.getPublic();
                System.out.println("Generated 512-bit RSA KeyPair!");
                System.out.println("Modulus: "+rsaPubKey.getModulus());
                System.out.println("Exponent: "+rsaPubKey.getPublicExponent());
                break;
            } catch (org.mozilla.jss.crypto.TokenRuntimeException TRExRSA512) {
                if (cntr==5) {
                    System.out.println("Generation of 512-bit RSA KeyPair Failed\n");
                    TRExRSA512.printStackTrace();
                }
            }
        }

        // 1024-bit RSA with default exponent
        System.out.println("Generating 1024-bit RSA KeyPair!");
        for (int cntr=0; cntr<5; cntr++ ) {
            try {
                kpg.initialize(1024);
                keyPair = kpg.genKeyPair();
                Assert._assert( keyPair.getPublic() instanceof RSAPublicKey);
                rsaPubKey = (RSAPublicKey) keyPair.getPublic();
                System.out.println("Generated 1024-bit RSA KeyPair!");
                System.out.println("Modulus: "+rsaPubKey.getModulus());
                System.out.println("Exponent: "+rsaPubKey.getPublicExponent());
                break;
            } catch (org.mozilla.jss.crypto.TokenRuntimeException TRExRSA1024) {
                if (cntr==5) {
                    System.out.println("Generation of 1024-bit RSA KeyPair Failed\n");
                    TRExRSA1024.printStackTrace();
                }
            }
        }

        // 512-bit RSA with exponent = 3
        System.out.println("Generating 512-bit RSA KeyPair with public exponent=3!");
        for (int cntr=0; cntr<5; cntr++ ) {
            try {
                rsaParams = new RSAParameterSpec(512, BigInteger.valueOf(3));
                kpg.initialize(rsaParams);
                keyPair = kpg.genKeyPair();
                Assert._assert( keyPair.getPublic() instanceof RSAPublicKey);
                rsaPubKey = (RSAPublicKey) keyPair.getPublic();
                System.out.println("Generated 512-bit RSA KeyPair with public exponent=3!");
                System.out.println("Modulus: "+rsaPubKey.getModulus());
                System.out.println("Exponent: "+rsaPubKey.getPublicExponent());
                break;
            } catch (org.mozilla.jss.crypto.TokenRuntimeException TRExRSA512Exp3) {
                if (cntr==5) {
                    System.out.println("Generation of 512-bit RSA KeyPair with public exponent=3 Failed\n");
                    TRExRSA512Exp3.printStackTrace();
                }
            }
        }

        // 512-bit DSA
        System.out.println("Generating 512-bit DSA KeyPair!");
        kpg = java.security.KeyPairGenerator.getInstance("DSA", "Mozilla-JSS");
        for (int cntr=0; cntr<5; cntr++ ) {
            try {
                kpg.initialize(512);
                keyPair = kpg.genKeyPair();
                Assert._assert( keyPair.getPublic() instanceof DSAPublicKey);
                dsaPubKey = (DSAPublicKey) keyPair.getPublic();
                System.out.println("Generated 512-bit DSA KeyPair!");
                dsaParams = dsaPubKey.getParams();
                System.out.println("P: "+dsaParams.getP());
                System.out.println("Q: "+dsaParams.getQ());
                System.out.println("G: "+dsaParams.getG());
                System.out.println("Y: "+dsaPubKey.getY());
                break;
            } catch (org.mozilla.jss.crypto.TokenRuntimeException TRExDSA512) {
                if (cntr==5) {
                    System.out.println("Generation of 512-bit DSA KeyPair Failed\n");
                    TRExDSA512.printStackTrace();
                }
            }
        }

        // 1024-bit DSA, passing in PQG params
        System.out.println("Generating 1024-bit DSA KeyPair with PQG params!");
        for (int cntr=0; cntr<5; cntr++ ) {
            try {
                kpg.initialize(PK11KeyPairGenerator.PQG1024);
                keyPair = kpg.genKeyPair();
                Assert._assert( keyPair.getPublic() instanceof DSAPublicKey);
                dsaPubKey = (DSAPublicKey) keyPair.getPublic();
                System.out.println("Generated 1024-bit DSA KeyPair with PQG params!");
                dsaParams = dsaPubKey.getParams();
                System.out.println("P: "+dsaParams.getP());
                System.out.println("Q: "+dsaParams.getQ());
                System.out.println("G: "+dsaParams.getG());
                System.out.println("Y: "+dsaPubKey.getY());
                break;
            } catch (org.mozilla.jss.crypto.TokenRuntimeException TRExDSA1024) {
                if (cntr==5) {
                    System.out.println("Generation of 1024-bit DSA KeyPair with PQG params Failed\n");
                    TRExDSA1024.printStackTrace();
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

        System.out.println("TestKeyGen passed");
        System.exit(0);
      } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
      }
    }
}
