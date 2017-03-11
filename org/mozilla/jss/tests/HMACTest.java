/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss.tests;

import java.io.*;
import java.security.MessageDigest;
import org.mozilla.jss.CryptoManager;
import java.security.Security;
import java.security.Provider;
import javax.crypto.*;
import javax.crypto.spec.*;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.SecretKeyFacade;
import org.mozilla.jss.util.PasswordCallback;

/**
 * HMAC is a hash function based message authentication code.
 * HMACTest compares the HMAC created by Mozilla, IBM and Sun JCE.
 *
 * @author  Sandeep.Konchady@Sun.COM
 * @version 1.0
 */
public class HMACTest {

    private CryptoManager cm;
    /**
     * JSS crypto provider name.
     */
    static final String MOZ_PROVIDER_NAME = "Mozilla-JSS";
    /**
     * List all the HMAC Algorithms that JSS implements.
     */
    static final String JSS_HMAC_Algs[] = {"HmacSHA1", "HmacSHA256",
        "HmacSHA384", "HmacSHA512"
    };

    public HMACTest(String[] argv) throws Exception {
        if (argv.length < 1) {
            System.out.println(
                    "Usage: java org.mozilla.jss.tests.HMACTest " +
                    "<dbdir> [password file only needed in FIPS mode]");
            System.exit(1);
        }
        CryptoManager.initialize(argv[0]);
        cm = CryptoManager.getInstance();

        if (cm.FIPSEnabled() == true) {
            System.out.println("\n\t\tFIPS enabled.\n");
            if (argv.length == 2) {
                CryptoToken tok = cm.getInternalCryptoToken();
                System.out.println("logging in to token: " + tok.getName());
                PasswordCallback cb = new FilePasswordCallback(argv[1]);
                tok.login(cb);
            }
        }
    }

    public boolean compareHMAC(String alg, SecretKeyFacade sk,
            String clearText)
            throws Exception {
        byte[] providerHmacOut;
        byte[] mozillaHmacOut;
        boolean bTested = false;

        //Get the Mozilla HMAC
        Mac mozillaHmac = Mac.getInstance(alg, MOZ_PROVIDER_NAME);
        mozillaHmac.init(sk);
        mozillaHmac.update(clearText.getBytes());
        mozillaHmacOut = mozillaHmac.doFinal();

        // loop through all configured providers; if they support the
        // algorithm compare the result to Mozilla's HMAC
        Provider[] providers = Security.getProviders("Mac." + alg);
        String provider = null;

        for (int i = 0; i < providers.length; ++i) {
            provider = providers[i].getName();
            //System.out.println ("Testing provider " + provider);
            if (provider.equals(MOZ_PROVIDER_NAME)) {
                continue;
            }
            Mac providerHmac = Mac.getInstance(alg, provider);
            providerHmac.init(sk);
            providerHmac.update(clearText.getBytes());
            providerHmacOut = providerHmac.doFinal();

            if (MessageDigest.isEqual(mozillaHmacOut, providerHmacOut)) {
                System.out.println(provider + " and " + MOZ_PROVIDER_NAME +
                        " give same " + alg);
                bTested = true;
            } else {
                throw new Exception("ERROR: " + provider + " and " +
                        MOZ_PROVIDER_NAME + " give different " +
                        alg);
            }
        }
        return bTested;
    }

    public void doHMAC(String alg, SecretKeyFacade sk, String clearText)
            throws Exception {
        byte[] mozillaHmacOut;

        //Get the Mozilla HMAC
        Mac mozillaHmac = Mac.getInstance(alg, MOZ_PROVIDER_NAME);
        mozillaHmac.init(sk);
        mozillaHmacOut = mozillaHmac.doFinal(clearText.getBytes());

        if (mozillaHmacOut.length == mozillaHmac.getMacLength()) {
            System.out.println(MOZ_PROVIDER_NAME + " supports " +
                    mozillaHmac.getAlgorithm() + "  and the output size is " + mozillaHmac.getMacLength());
        } else {
            throw new Exception("ERROR: hmac output size is " +
                    mozillaHmacOut.length + ", should be " +
                    mozillaHmac.getMacLength());
        }
    }

    public boolean fipsMode() {
        return cm.FIPSEnabled();
    }

    /**
     * Main test method.
     * @param argv
     */
    public static void main(String[] argv) {

        try {
            HMACTest hmacTest = new HMACTest(argv);

            //The secret key must be a JSS key. That is, it must be an 
            //instanceof org.mozilla.jss.crypto.SecretKeyFacade.

            //Generate the secret key using PKCS # 5 password Based Encryption
            //we have to specify a salt and an iteration count.  

            PBEKeySpec pbeKeySpec;
            SecretKeyFactory keyFac;
            SecretKeyFacade sk;
            byte[] salt = {
                (byte) 0x0a, (byte) 0x6d, (byte) 0x07, (byte) 0xba,
                (byte) 0x1e, (byte) 0xbd, (byte) 0x72, (byte) 0xf1
            };
            int iterationCount = 7;

            pbeKeySpec = new PBEKeySpec("password".toCharArray(),
                    salt, iterationCount);
            keyFac = SecretKeyFactory.getInstance("PBEWithSHA1AndDES3",
                    "Mozilla-JSS");
            sk = (SecretKeyFacade) keyFac.generateSecret(pbeKeySpec);

            /////////////////////////////////////////////////////////////
            // Test all available algorithms
            /////////////////////////////////////////////////////////////
            String clearText = new String("FireFox and Thunderbird rule");
            for (int i = 0; i < JSS_HMAC_Algs.length; i++) {
                if (hmacTest.fipsMode()) {
                    //In FIPS Mode only test JSS due to NSS prevents
                    //key data from being extracted above the
                    //NSS cryptographic boundary when FIPS mode
                    //is enabled.
                    //note there is a bug with HmacSHA512 in fipsmode.
                    //https://bugzilla.mozilla.org/show_bug.cgi?id=436907
                    if (!JSS_HMAC_Algs[i].equals("HmacSHA512")) {
                        hmacTest.doHMAC(JSS_HMAC_Algs[i], sk, clearText);
                    }
                } else {
                    // compare MOZ_PROVIDER_NAME implementation with all
                    // providers that also support the given algorithm
                    if (!hmacTest.compareHMAC(
                            JSS_HMAC_Algs[i], sk, clearText)) {
                        // no provider to compare results with so just test JSS
                        hmacTest.doHMAC(JSS_HMAC_Algs[i], sk, clearText);
                    }
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
        System.exit(0);
    }
}

