/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
/* This program demonstrates how to sign data with keys from JSS
 *
 * Most of this code is deprecated look at JCASigTest.java
 *
 * java -cp ./jss4.jar org.mozilla.jss.tests.SigTest . 
 *               passwords "Internal Key Storage Token"
 *
 * The token name can be either the name of a hardware token, or
 * one of the internal tokens:
 *  Internal Crypto Services Token
 *  Internal Key Storage Token    (keys stored in key4.db)
 *
 * @see org.mozilla.jss.tests.JCASigTest
 * @deprecated Use the JCA interface instead
 */
package org.mozilla.jss.tests;

import org.mozilla.jss.crypto.*;
import org.mozilla.jss.crypto.Signature;
import org.mozilla.jss.crypto.KeyPairGenerator;
import org.mozilla.jss.crypto.KeyPairGeneratorSpi;
import java.security.*;
import java.util.*;
import org.mozilla.jss.pkcs11.*;
import org.mozilla.jss.*;
import org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage;

public class SigTest {

    public static void usage() {
        System.out.println(
                "Usage: java org.mozilla.jss.crypto.SigTest <dbdir> <pwfile>" +
                " [tokenname]");
    }

    public static void main(String args[]) {
        try {
            CryptoToken token;
            CryptoManager manager;
            byte[] data = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9};
            byte[] signature;
            Signature signer;
            PublicKey pubk;
            KeyPairGenerator kpgen;
            KeyPair keyPair;

            if (args.length < 2 || args.length > 3) {
                usage();
                System.exit(1);
            }
            String dbdir = args[0];


            CryptoManager.InitializationValues vals = 
                    new CryptoManager.InitializationValues(args[0]);
            CryptoManager.initialize(vals);
            manager = CryptoManager.getInstance();
            manager.setPasswordCallback(new FilePasswordCallback(args[1]));
            

            /* Print out list of available tokens */
            Enumeration en = manager.getAllTokens();
            System.out.println("Available tokens:");
            while (en.hasMoreElements()) {
                PK11Token p = (PK11Token) en.nextElement();
                System.out.println(" token : " + p.getName());
            }
            
            if (args.length >= 3) {
                token = manager.getTokenByName(args[2]);
            } else {
                //get default internal key storage token
                token = manager.getInternalKeyStorageToken();
            }
            // Generate an RSA keypair
            kpgen = token.getKeyPairGenerator(KeyPairAlgorithm.RSA);
            kpgen.initialize(1024);
            KeyPairGeneratorSpi.Usage usages[] = {
                KeyPairGeneratorSpi.Usage.SIGN,
                KeyPairGeneratorSpi.Usage.VERIFY};
            KeyPairGeneratorSpi.Usage usages_mask[] = {
                KeyPairGeneratorSpi.Usage.SIGN,
                KeyPairGeneratorSpi.Usage.VERIFY};

            kpgen.setKeyPairUsages(usages, usages_mask);
            keyPair = kpgen.genKeyPair();

            // RSA MD5
            signer = token.getSignatureContext(
                    SignatureAlgorithm.RSASignatureWithMD5Digest);
            System.out.println("Created a signing context");
            signer.initSign(
                    (org.mozilla.jss.crypto.PrivateKey) keyPair.getPrivate());
            System.out.println("initialized the signing operation");

            signer.update(data);
            System.out.println("updated signature with data");
            signature = signer.sign();
            System.out.println("Successfully signed!");

            signer.initVerify(keyPair.getPublic());
            System.out.println("initialized verification");
            signer.update(data);
            System.out.println("updated verification with data");
            if (signer.verify(signature)) {
                System.out.println("Signature Verified Successfully!");
            } else {
                throw new Exception("ERROR: Signature failed to verify.");
            }

            System.out.println("SigTest passed.");
            System.exit(0);
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }
}
