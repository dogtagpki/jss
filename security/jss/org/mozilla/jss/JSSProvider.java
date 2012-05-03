/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss;

public final class JSSProvider extends java.security.Provider {

    /********************************************************************/
    /* The VERSION Strings should be updated in the following           */
    /* files everytime a new release of JSS is generated:               */
    /*                                                                  */
    /* org/mozilla/jss/CryptoManager.java                               */
    /* org/mozilla/jss/JSSProvider.java                                 */
    /* org/mozilla/jss/util/jssver.h                                    */
    /* lib/manifest.mn                                                  */
    /* mozilla/security/jss/manifest.mn                                 */
    /*                                                                  */
    /********************************************************************/

    private static int JSS_MAJOR_VERSION  = 4;
    private static int JSS_MINOR_VERSION  = 3;
    private static int JSS_PATCH_VERSION  = 2;
    private static double JSS_VERSION     = JSS_MAJOR_VERSION +
                                           (JSS_MINOR_VERSION * 100 +
                                            JSS_PATCH_VERSION)/10000.0;

    public JSSProvider() {
        super("Mozilla-JSS", JSS_VERSION,
                "Provides Signature, Message Digesting, and RNG");

        /////////////////////////////////////////////////////////////
        // Signature
        /////////////////////////////////////////////////////////////
        put("Signature.SHA1withDSA",
            "org.mozilla.jss.provider.java.security.JSSSignatureSpi$DSA");

        put("Alg.Alias.Signature.DSA", "SHA1withDSA");
        put("Alg.Alias.Signature.DSS", "SHA1withDSA");
        put("Alg.Alias.Signature.SHA/DSA", "SHA1withDSA");
        put("Alg.Alias.Signature.SHA-1/DSA", "SHA1withDSA");
        put("Alg.Alias.Signature.SHA1/DSA", "SHA1withDSA");
        put("Alg.Alias.Signature.DSAWithSHA1", "SHA1withDSA");
        put("Alg.Alias.Signature.SHAwithDSA", "SHA1withDSA");

        put("Signature.MD5/RSA",
            "org.mozilla.jss.provider.java.security.JSSSignatureSpi$MD5RSA");
        put("Alg.Alias.Signature.MD5withRSA", "MD5/RSA");

        put("Signature.MD2/RSA",
            "org.mozilla.jss.provider.java.security.JSSSignatureSpi$MD2RSA");

        put("Signature.SHA-1/RSA",
            "org.mozilla.jss.provider.java.security.JSSSignatureSpi$SHA1RSA");
        put("Alg.Alias.Signature.SHA1/RSA", "SHA-1/RSA");
        put("Alg.Alias.Signature.SHA1withRSA", "SHA-1/RSA");

        put("Signature.SHA-256/RSA",
            "org.mozilla.jss.provider.java.security.JSSSignatureSpi$SHA256RSA");
        put("Alg.Alias.Signature.SHA256/RSA", "SHA-256/RSA");
        put("Alg.Alias.Signature.SHA256withRSA", "SHA-256/RSA");

        put("Signature.SHA-384/RSA",
            "org.mozilla.jss.provider.java.security.JSSSignatureSpi$SHA384RSA");
        put("Alg.Alias.Signature.SHA384/RSA", "SHA-384/RSA");
        put("Alg.Alias.Signature.SHA384withRSA", "SHA-384/RSA");

        put("Signature.SHA-512/RSA",
            "org.mozilla.jss.provider.java.security.JSSSignatureSpi$SHA512RSA");
        put("Alg.Alias.Signature.SHA512/RSA", "SHA-512/RSA");
        put("Alg.Alias.Signature.SHA512withRSA", "SHA-512/RSA");
// ECC
        put("Signature.SHA1withEC",
            "org.mozilla.jss.provider.java.security.JSSSignatureSpi$SHA1EC");
        put("Alg.Alias.Signature.EC", "SHA1withEC");
        put("Alg.Alias.Signature.ECC", "SHA1withEC");
        put("Alg.Alias.Signature.ECDSA", "SHA1withEC");
        put("Alg.Alias.Signature.SHA/EC", "SHA1withEC");
        put("Alg.Alias.Signature.SHA1/EC", "SHA1withEC");
        put("Alg.Alias.Signature.SHA-1/EC", "SHA1withEC");
        put("Alg.Alias.Signature.SHA/ECDSA", "SHA1withEC");
        put("Alg.Alias.Signature.SHA1/ECDSA", "SHA1withEC");

        put("Signature.SHA256withEC",
            "org.mozilla.jss.provider.java.security.JSSSignatureSpi$SHA256EC");
        put("Alg.Alias.Signature.SHA256/EC", "SHA256withEC");
        put("Alg.Alias.Signature.SHA-256/EC", "SHA256withEC");

        put("Signature.SHA384withEC",
            "org.mozilla.jss.provider.java.security.JSSSignatureSpi$SHA384EC");
        put("Alg.Alias.Signature.SHA384/EC", "SHA384withEC");
        put("Alg.Alias.Signature.SHA-384/EC", "SHA384withEC");

        put("Signature.SHA512withEC",
            "org.mozilla.jss.provider.java.security.JSSSignatureSpi$SHA512EC");
        put("Alg.Alias.Signature.SHA512/EC", "SHA512withEC");
        put("Alg.Alias.Signature.SHA-512/EC", "SHA512withEC");

        /////////////////////////////////////////////////////////////
        // Message Digesting
        /////////////////////////////////////////////////////////////

        put("MessageDigest.SHA-1",
                "org.mozilla.jss.provider.java.security.JSSMessageDigestSpi$SHA1");
        put("MessageDigest.MD2",
                "org.mozilla.jss.provider.java.security.JSSMessageDigestSpi$MD2");
        put("MessageDigest.MD5",
                "org.mozilla.jss.provider.java.security.JSSMessageDigestSpi$MD5");
        put("MessageDigest.SHA-256",
                "org.mozilla.jss.provider.java.security.JSSMessageDigestSpi$SHA256");
        put("MessageDigest.SHA-384",
                "org.mozilla.jss.provider.java.security.JSSMessageDigestSpi$SHA384");
        put("MessageDigest.SHA-512",
                "org.mozilla.jss.provider.java.security.JSSMessageDigestSpi$SHA512");

        put("Alg.Alias.MessageDigest.SHA1", "SHA-1");
        put("Alg.Alias.MessageDigest.SHA", "SHA-1");
        put("Alg.Alias.MessageDigest.SHA256", "SHA-256");
        put("Alg.Alias.MessageDigest.SHA384", "SHA-384");
        put("Alg.Alias.MessageDigest.SHA512", "SHA-512");

        /////////////////////////////////////////////////////////////
        // SecureRandom
        /////////////////////////////////////////////////////////////
        put("SecureRandom.pkcs11prng",
            "org.mozilla.jss.provider.java.security.JSSSecureRandomSpi");

        /////////////////////////////////////////////////////////////
        // KeyPairGenerator
        /////////////////////////////////////////////////////////////
        put("KeyPairGenerator.RSA",
            "org.mozilla.jss.provider.java.security.JSSKeyPairGeneratorSpi$RSA");
        put("KeyPairGenerator.DSA",
            "org.mozilla.jss.provider.java.security.JSSKeyPairGeneratorSpi$DSA");
        put("KeyPairGenerator.EC",
            "org.mozilla.jss.provider.java.security.JSSKeyPairGeneratorSpi$EC");

        /////////////////////////////////////////////////////////////
        // KeyFactory
        /////////////////////////////////////////////////////////////
        put("KeyFactory.RSA",
            "org.mozilla.jss.provider.java.security.KeyFactorySpi1_2");
        put("KeyFactory.DSA",
            "org.mozilla.jss.provider.java.security.KeyFactorySpi1_2");
        put("KeyFactory.EC",
            "org.mozilla.jss.provider.java.security.KeyFactorySpi1_2");

        /////////////////////////////////////////////////////////////
        // AlgorithmParameters
        /////////////////////////////////////////////////////////////
        put("AlgorithmParameters.IvAlgorithmParameters",
            "org.mozilla.jss.provider.java.security.IvAlgorithmParameters");
        put("AlgorithmParameters.RC2AlgorithmParameters",
            "org.mozilla.jss.provider.java.security.RC2AlgorithmParameters");

        /////////////////////////////////////////////////////////////
        // Cipher
        /////////////////////////////////////////////////////////////
        put("Cipher.DES",
            "org.mozilla.jss.provider.javax.crypto.JSSCipherSpi$DES");
        put("Cipher.DESede",
            "org.mozilla.jss.provider.javax.crypto.JSSCipherSpi$DESede");
        put("Alg.Alias.Cipher.DES3", "DESede");
        put("Cipher.AES",
            "org.mozilla.jss.provider.javax.crypto.JSSCipherSpi$AES");
        put("Cipher.RC4",
            "org.mozilla.jss.provider.javax.crypto.JSSCipherSpi$RC4");
        put("Cipher.RSA",
            "org.mozilla.jss.provider.javax.crypto.JSSCipherSpi$RSA");
        put("Cipher.RC2",
            "org.mozilla.jss.provider.javax.crypto.JSSCipherSpi$RC2");

        /////////////////////////////////////////////////////////////
        // KeyGenerator
        /////////////////////////////////////////////////////////////
        put("KeyGenerator.DES",
            "org.mozilla.jss.provider.javax.crypto.JSSKeyGeneratorSpi$DES");
        put("KeyGenerator.DESede",
            "org.mozilla.jss.provider.javax.crypto.JSSKeyGeneratorSpi$DESede");
        put("Alg.Alias.KeyGenerator.DES3", "DESede");
        put("KeyGenerator.AES",
            "org.mozilla.jss.provider.javax.crypto.JSSKeyGeneratorSpi$AES");
        put("KeyGenerator.RC4",
            "org.mozilla.jss.provider.javax.crypto.JSSKeyGeneratorSpi$RC4");
        put("KeyGenerator.RC2",
            "org.mozilla.jss.provider.javax.crypto.JSSKeyGeneratorSpi$RC2");
        put("KeyGenerator.HmacSHA1",
           "org.mozilla.jss.provider.javax.crypto.JSSKeyGeneratorSpi$HmacSHA1");
        put("KeyGenerator.PBAHmacSHA1",
           "org.mozilla.jss.provider.javax.crypto.JSSKeyGeneratorSpi$PBAHmacSHA1");

        /////////////////////////////////////////////////////////////
        // SecretKeyFactory
        /////////////////////////////////////////////////////////////
        put("SecretKeyFactory.DES",
            "org.mozilla.jss.provider.javax.crypto.JSSSecretKeyFactorySpi$DES");
        put("SecretKeyFactory.DESede",
         "org.mozilla.jss.provider.javax.crypto.JSSSecretKeyFactorySpi$DESede");
        put("Alg.Alias.SecretKeyFactory.DES3", "DESede");
        put("SecretKeyFactory.AES",
            "org.mozilla.jss.provider.javax.crypto.JSSSecretKeyFactorySpi$AES");
        put("SecretKeyFactory.RC4",
            "org.mozilla.jss.provider.javax.crypto.JSSSecretKeyFactorySpi$RC4");
        put("SecretKeyFactory.RC2",
            "org.mozilla.jss.provider.javax.crypto.JSSSecretKeyFactorySpi$RC2");
        put("SecretKeyFactory.HmacSHA1",
            "org.mozilla.jss.provider.javax.crypto.JSSSecretKeyFactorySpi$HmacSHA1");
        put("SecretKeyFactory.PBAHmacSHA1",
            "org.mozilla.jss.provider.javax.crypto.JSSSecretKeyFactorySpi$PBAHmacSHA1");
        put("SecretKeyFactory.PBEWithMD5AndDES",
            "org.mozilla.jss.provider.javax.crypto.JSSSecretKeyFactorySpi$PBE_MD5_DES_CBC");
        put("SecretKeyFactory.PBEWithSHA1AndDES",
            "org.mozilla.jss.provider.javax.crypto.JSSSecretKeyFactorySpi$PBE_SHA1_DES_CBC");
        put("SecretKeyFactory.PBEWithSHA1AndDESede",
            "org.mozilla.jss.provider.javax.crypto.JSSSecretKeyFactorySpi$PBE_SHA1_DES3_CBC");
        put("Alg.Alias.SecretKeyFactory.PBEWithSHA1AndDES3", "PBEWithSHA1AndDESede");
        put("SecretKeyFactory.PBEWithSHA1And128RC4",
            "org.mozilla.jss.provider.javax.crypto.JSSSecretKeyFactorySpi$PBE_SHA1_RC4_128");


        /////////////////////////////////////////////////////////////
        // MAC
        /////////////////////////////////////////////////////////////
        put("Mac.HmacSHA1",
            "org.mozilla.jss.provider.javax.crypto.JSSMacSpi$HmacSHA1");
        put("Alg.Alias.Mac.Hmac-SHA1", "HmacSHA1");
        put("Mac.HmacSHA256",
            "org.mozilla.jss.provider.javax.crypto.JSSMacSpi$HmacSHA256");
        put("Alg.Alias.Mac.Hmac-SHA256", "HmacSHA256");
        put("Mac.HmacSHA384",
            "org.mozilla.jss.provider.javax.crypto.JSSMacSpi$HmacSHA384");
        put("Alg.Alias.Mac.Hmac-SHA384", "HmacSHA384");
        put("Mac.HmacSHA512",
            "org.mozilla.jss.provider.javax.crypto.JSSMacSpi$HmacSHA512");
        put("Alg.Alias.Mac.Hmac-SHA512", "HmacSHA512");

    }

    public String toString() {
        String mozillaProviderVersion = JSS_MAJOR_VERSION + "." + 
                                        JSS_MINOR_VERSION;
        if ( JSS_PATCH_VERSION != 0 ) {
            mozillaProviderVersion = mozillaProviderVersion + "." +
                                     JSS_PATCH_VERSION;
        }

        return "Mozilla-JSS version " + mozillaProviderVersion;
    }
}
