/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss.tests;

import java.io.*;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.util.Debug;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.Security;

public class DigestTest {

    /**
     * This is the name of the JSS crypto provider for use with
     * MessageDigest.getInstance().
     */
    static final String MOZ_PROVIDER_NAME = "Mozilla-JSS";

    /**
     * List all the Digest Algorithms that JSS implements.
     */
    static final String JSS_Digest_Algs[] = { "MD2", "MD5", "SHA-1",
                                            "SHA-256", "SHA-384","SHA-512"};

    public static boolean messageDigestCompare(String alg, byte[] toBeDigested)
    throws Exception {
        byte[] otherDigestOut;
        byte[] mozillaDigestOut;
        boolean bTested = false;

        // get the digest for the Mozilla-JSS provider
        java.security.MessageDigest mozillaDigest =
                java.security.MessageDigest.getInstance(alg,
                MOZ_PROVIDER_NAME);
        mozillaDigestOut = mozillaDigest.digest(toBeDigested);

        // loop through all the providers that support the algorithm
        // compare the result to Mozilla-JSS's digest
        Provider[] providers = Security.getProviders("MessageDigest." + alg);
        String provider = null;

        for (int i = 0; i < providers.length; ++i) {

            provider = providers[i].getName();
            if (provider.equals(MOZ_PROVIDER_NAME)) {
                continue;
            }

            java.security.MessageDigest otherDigest =
                    java.security.MessageDigest.getInstance(alg, provider);

            otherDigestOut =
                    otherDigest.digest(toBeDigested);

            if( MessageDigest.isEqual(mozillaDigestOut, otherDigestOut) ) {
                System.out.println(provider + " and " + MOZ_PROVIDER_NAME +
                                   " give same " + alg + " message digests");
                bTested = true;
            } else {
                throw new Exception("ERROR: " + provider + " and " +
                                    MOZ_PROVIDER_NAME + " give different " +
                                    alg + " message digests");
            }
        }

        return bTested;
    }

    public static boolean testJSSDigest(String alg, byte[] toBeDigested)
    throws Exception {
        byte[] mozillaDigestOut;
 
        java.security.MessageDigest mozillaDigest =
                java.security.MessageDigest.getInstance(alg, MOZ_PROVIDER_NAME);

        mozillaDigestOut = mozillaDigest.digest(toBeDigested);

        if( mozillaDigestOut.length == mozillaDigest.getDigestLength() ) {
            System.out.println(mozillaDigest.getAlgorithm() + " " +
                    " digest output size is " + mozillaDigestOut.length);
        } else {
            throw new Exception("ERROR: digest output size is "+
                    mozillaDigestOut.length + ", should be "+ 
                    mozillaDigest.getDigestLength() );
        }
 
        return true;
    }


    public static void main(String []argv) {

        try {

            if( argv.length != 2 ) {
                System.out.println(
                        "Usage: java org.mozilla.jss.tests.DigestTest " +
                        "<dbdir> <File>");
                System.exit(1);
            }
            String dbdir = argv[0];
            FileInputStream fis = new FileInputStream(argv[1]);
            byte[] toBeDigested = new byte[ fis.available() ];
            int read = fis.read( toBeDigested );
            System.out.println(read + " bytes to be digested");

            CryptoManager.initialize(dbdir);

            Debug.setLevel(Debug.OBNOXIOUS);

            /////////////////////////////////////////////////////////////
            // Test all available algorithms
            /////////////////////////////////////////////////////////////
            String javaVersion = System.getProperty("java.version");
            System.out.println("The Java version is: " + javaVersion);

            for (int i = 0; i < JSS_Digest_Algs.length; i++) {
                // compare Mozilla-JSS implementation with all providers
                // that also support the given algorithm
                if (messageDigestCompare(JSS_Digest_Algs[i], toBeDigested) 
                    == false) {
                    // no provider to compare results with
                    testJSSDigest(JSS_Digest_Algs[i], toBeDigested);
                }
            }

            //HMAC examples in org.mozilla.jss.tests.HMACTest

        } catch( Exception e ) {
            e.printStackTrace();
            System.exit(1);
        }
        System.exit(0);
    }
}
