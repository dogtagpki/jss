/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
/* This program demonstrates how to sign data with keys from JSS
 *
 * The token name can be either the name of a hardware token, or
 * one of the internal tokens:
 *  Internal Crypto Services Token
 *  Internal Key Storage Token    (keys stored in key4.db)
 */
package org.mozilla.jss.tests;

import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Enumeration;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.KeyPairAlgorithm;
import org.mozilla.jss.crypto.KeyPairGenerator;
import org.mozilla.jss.crypto.KeyPairGeneratorSpi;
import org.mozilla.jss.crypto.Policy;
import org.mozilla.jss.crypto.Signature;
import org.mozilla.jss.crypto.SignatureAlgorithm;
import org.mozilla.jss.pkcs11.PK11Token;

public class SigTest {

    public static void usage() {
        System.out.println(
                "Usage: java org.mozilla.jss.crypto.SigTest <dbdir> <pwfile>" +
                " [tokenname]");
    }

    public static void main(String args[]) throws Exception {
        CryptoToken token;
        CryptoManager manager;
        byte[] data = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9};
        byte[] signature;
        Signature signer;
        Signature signerPSS;
        PublicKey pubk;
        KeyPairGenerator kpgen;
        KeyPair keyPair;

        if (args.length < 2 || args.length > 3) {
            usage();
            System.exit(1);
        }

        manager = CryptoManager.getInstance();
        manager.setPasswordCallback(new FilePasswordCallback(args[1]));


        /* Print out list of available tokens */
        Enumeration<CryptoToken> en = manager.getAllTokens();
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
        kpgen.initialize(Policy.RSA_MINIMUM_KEY_SIZE);
        KeyPairGeneratorSpi.Usage usages[] = {
            KeyPairGeneratorSpi.Usage.SIGN,
            KeyPairGeneratorSpi.Usage.VERIFY};
        KeyPairGeneratorSpi.Usage usages_mask[] = {
            KeyPairGeneratorSpi.Usage.SIGN,
            KeyPairGeneratorSpi.Usage.VERIFY};

        kpgen.setKeyPairUsages(usages, usages_mask);
        keyPair = kpgen.genKeyPair();

        // RSA SHA256
        signer = token.getSignatureContext(
                SignatureAlgorithm.RSASignatureWithSHA256Digest);
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

        signerPSS = token.getSignatureContext(
                SignatureAlgorithm.RSAPSSSignatureWithSHA256Digest);
        signerPSS.initSign(
                (org.mozilla.jss.crypto.PrivateKey) keyPair.getPrivate());

        signerPSS.update(data);
        signature = signerPSS.sign();
        System.out.println("PSS Successfully signed!");

        signerPSS.initVerify(keyPair.getPublic());
        signerPSS.update(data);
        System.out.println("updated verification with data");
        if (signerPSS.verify(signature)) {
            System.out.println("PSS Signature Verified Successfully!");
        } else {
            throw new Exception("ERROR: PSS Signature failed to verify.");
        }

        System.out.println("SigTest passed.");
    }
}
