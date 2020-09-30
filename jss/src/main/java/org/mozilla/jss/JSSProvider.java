/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss;

import java.lang.NullPointerException;
import java.security.Provider;

import java.io.InputStream;

public final class JSSProvider extends java.security.Provider {
    public static boolean ENABLE_JSSENGINE = true;

    private static final long serialVersionUID = 1L;
    /********************************************************************/
    /* The VERSION Strings should be updated everytime a new release    */
    /* of JSS is generated. Note that this is done by changing          */
    /* cmake/JSSConfig.cmake.                                           */
    /********************************************************************/
    private static int JSS_MAJOR_VERSION  = CryptoManager.getJSSMajorVersion();
    private static int JSS_MINOR_VERSION  = CryptoManager.getJSSMinorVersion();
    private static int JSS_PATCH_VERSION  = CryptoManager.getJSSPatchVersion();
    private static double JSS_VERSION     = JSS_MAJOR_VERSION +
                                           (JSS_MINOR_VERSION * 100 +
                                            JSS_PATCH_VERSION)/10000.0;

    private static JSSLoader loader = new JSSLoader();

    private static CryptoManager cm;

    public JSSProvider() {
        this(CryptoManager.isInitialized());
    }

    public JSSProvider(boolean initialize) {
        super("Mozilla-JSS", JSS_VERSION,
                "Provides Signature, Message Digesting, and RNG");

        if (initialize) {
            initializeProvider();
        }
    }

    public JSSProvider(String config_path) throws Exception {
        this(false);

        configure(config_path);
    }

    public JSSProvider(InputStream config) throws Exception {
        this(false);

        cm = loader.init(config);
        initializeProvider();
    }

    /**
     * Configure this instance of JSSProvider with the specified path
     * to a JSS configuration properties file.
     *
     * See JSSLoader's class description for a description of the JSS
     * configuration properties file and known values.
     *
     * If the JSSProvider is already loaded, this is a no-op.
     */
    public Provider configure(String arg) {
        try {
            cm = loader.init(arg);
        } catch (NullPointerException npe) {
            throw npe;
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage(), e);
        }

        initializeProvider();

        return this;
    }

    /**
     * Return the CryptoManager this instance was initialized with.
     */
    public CryptoManager getCryptoManager() {
        if (cm == null) {
            try {
                cm = CryptoManager.getInstance();
            } catch (NotInitializedException nie) {}
        }
        return cm;
    }

    protected void initializeProvider() {
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

        put("Signature.RSASSA-PSS",
            "org.mozilla.jss.provider.java.security.JSSSignatureSpi$RSAPSSSignature");

        put("Alg.Alias.Signature.1.2.840.113549.1.1.10",     "RSASSA-PSS");
        put("Alg.Alias.Signature.OID.1.2.840.113549.1.1.10", "RSASSA-PSS");

        put("Signature.SHA-256/RSA/PSS",
            "org.mozilla.jss.provider.java.security.JSSSignatureSpi$SHA256RSAPSS");

        put("Alg.Alias.Signature.SHA256withRSA/PSS","SHA-256/RSA/PSS");

        put("Signature.SHA-384/RSA/PSS",
            "org.mozilla.jss.provider.java.security.JSSSignatureSpi$SHA384RSAPSS");

        put("Alg.Alias.Signature.SHA384withRSA/PSS","SHA-384/RSA/PSS");

        put("Signature.SHA-512/RSA/PSS",
            "org.mozilla.jss.provider.java.security.JSSSignatureSpi$SHA512RSAPSS");

        put("Alg.Alias.Signature.SHA512withRSA/PSS","SHA-512/RSA/PSS");


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
        put("Alg.Alias.Signature.SHA1withECDSA", "SHA1withEC"); //JCE Standard Name

        put("Signature.SHA256withEC",
            "org.mozilla.jss.provider.java.security.JSSSignatureSpi$SHA256EC");
        put("Alg.Alias.Signature.SHA256/EC", "SHA256withEC");
        put("Alg.Alias.Signature.SHA-256/EC", "SHA256withEC");
        put("Alg.Alias.Signature.SHA256withECDSA", "SHA256withEC"); //JCE Standard Name

        put("Signature.SHA384withEC",
            "org.mozilla.jss.provider.java.security.JSSSignatureSpi$SHA384EC");
        put("Alg.Alias.Signature.SHA384/EC", "SHA384withEC");
        put("Alg.Alias.Signature.SHA-384/EC", "SHA384withEC");
        put("Alg.Alias.Signature.SHA384withECDSA", "SHA384withEC"); //JCE Standard Name

        put("Signature.SHA512withEC",
            "org.mozilla.jss.provider.java.security.JSSSignatureSpi$SHA512EC");
        put("Alg.Alias.Signature.SHA512/EC", "SHA512withEC");
        put("Alg.Alias.Signature.SHA-512/EC", "SHA512withEC");
        put("Alg.Alias.Signature.SHA512withECDSA", "SHA512withEC"); //JCE Standard Name

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
        // KeyStore
        /////////////////////////////////////////////////////////////
        put("KeyStore.PKCS11",
                "org.mozilla.jss.provider.java.security.JSSKeyStoreSpi");

        /////////////////////////////////////////////////////////////
        // AlgorithmParameters
        /////////////////////////////////////////////////////////////
        put("AlgorithmParameters.IvAlgorithmParameters",
            "org.mozilla.jss.provider.java.security.IvAlgorithmParameters");
        put("AlgorithmParameters.RC2AlgorithmParameters",
            "org.mozilla.jss.provider.java.security.RC2AlgorithmParameters");

        put("AlgorithmParameters.RSAPSSAlgorithmParameters",
            "org.mozilla.jss.provider.java.security.RSAPSSAlgorithmParameters");

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
        String kg_spi = "org.mozilla.jss.provider.javax.crypto.JSSKeyGeneratorSpi";

        put("KeyGenerator.DES", kg_spi + "$DES");
        put("KeyGenerator.DESede", kg_spi + "$DESede");
        put("Alg.Alias.KeyGenerator.DES3", "DESede");
        put("KeyGenerator.AES", kg_spi + "$AES");
        put("KeyGenerator.RC4", kg_spi + "$RC4");
        put("KeyGenerator.RC2", kg_spi + "$RC2");
        put("KeyGenerator.HmacSHA1", kg_spi + "$HmacSHA1");
        put("KeyGenerator.PBAHmacSHA1", kg_spi + "$PBAHmacSHA1");
        put("KeyGenerator.HmacSHA256", kg_spi + "$HmacSHA256");
        put("KeyGenerator.HmacSHA384", kg_spi + "$HmacSHA384");
        put("KeyGenerator.HmacSHA512", kg_spi + "$HmacSHA512");
        // KBKDF: Counter
        put("KeyGenerator.KbkdfCounter", kg_spi + "$KbkdfCounter");
        put("Alg.Alias.KeyGenerator.KBKDF-Counter", "KbkdfCounter");
        put("Alg.Alias.KeyGenerator.SP800-108-KDF-Counter", "KbkdfCounter");
        put("Alg.Alias.KeyGenerator.SP800-108-Counter", "KbkdfCounter");
        put("Alg.Alias.KeyGenerator.CounterKbkdf", "KbkdfCounter");
        // KBKDF: Counter (data)
        put("KeyGenerator.KbkdfCounterData", kg_spi + "$KbkdfCounterData");
        put("Alg.Alias.KeyGenerator.KBKDF-Counter-Data", "KbkdfCounterData");
        put("Alg.Alias.KeyGenerator.SP800-108-KDF-Counter-Data", "KbkdfCounterData");
        put("Alg.Alias.KeyGenerator.SP800-108-Counter-Data", "KbkdfCounterData");
        put("Alg.Alias.KeyGenerator.CounterKbkdf-Data", "KbkdfCounterData");
        // KBKDF: Feedback
        put("KeyGenerator.KbkdfFeedback", kg_spi + "$KbkdfFeedback");
        put("Alg.Alias.KeyGenerator.KBKDF-Feedback", "KbkdfFeedback");
        put("Alg.Alias.KeyGenerator.SP800-108-KDF-Feedback", "KbkdfFeedback");
        put("Alg.Alias.KeyGenerator.SP800-108-Feedback", "KbkdfFeedback");
        put("Alg.Alias.KeyGenerator.FeedbackKbkdf", "KbkdfFeedback");
        // KBKDF: Feedback (data)
        put("KeyGenerator.KbkdfFeedbackData", kg_spi + "$KbkdfFeedbackData");
        put("Alg.Alias.KeyGenerator.KBKDF-Feedback-Data", "KbkdfFeedbackData");
        put("Alg.Alias.KeyGenerator.SP800-108-KDF-Feedback-Data", "KbkdfFeedbackData");
        put("Alg.Alias.KeyGenerator.SP800-108-Feedback-Data", "KbkdfFeedbackData");
        put("Alg.Alias.KeyGenerator.FeedbackKbkdf-Data", "KbkdfFeedbackData");
        // KBKDF: Double Pipeline -- sometimes Pipeline KBKDF
        put("KeyGenerator.KbkdfDoublePipeline", kg_spi + "$KbkdfDoublePipeline");
        put("Alg.Alias.KeyGenerator.KBKDF-DoublePipeline", "KbkdfDoublePipeline");
        put("Alg.Alias.KeyGenerator.SP800-108-KDF-DoublePipeline", "KbkdfDoublePipeline");
        put("Alg.Alias.KeyGenerator.SP800-108-DoublePipeline", "KbkdfDoublePipeline");
        put("Alg.Alias.KeyGenerator.DoublePipelineKbkdf", "KbkdfDoublePipeline");
        put("Alg.Alias.KeyGenerator.KbkdfPipeline", "KbkdfDoublePipeline");
        put("Alg.Alias.KeyGenerator.KBKDF-Pipeline", "KbkdfDoublePipeline");
        put("Alg.Alias.KeyGenerator.SP800-108-KDF-Pipeline", "KbkdfDoublePipeline");
        put("Alg.Alias.KeyGenerator.SP800-108-Pipeline", "KbkdfDoublePipeline");
        put("Alg.Alias.KeyGenerator.PipelineKbkdf", "KbkdfDoublePipeline");
        // KBKDF: Double Pipeline (data) -- sometimes Pipeline KBKDF (data)
        put("KeyGenerator.KbkdfDoublePipelineData", kg_spi + "$KbkdfDoublePipelineData");
        put("Alg.Alias.KeyGenerator.KBKDF-DoublePipeline-Data", "KbkdfDoublePipelineData");
        put("Alg.Alias.KeyGenerator.SP800-108-KDF-DoublePipeline-Data", "KbkdfDoublePipelineData");
        put("Alg.Alias.KeyGenerator.SP800-108-DoublePipeline-Data", "KbkdfDoublePipelineData");
        put("Alg.Alias.KeyGenerator.DoublePipelineKbkdf-Data", "KbkdfDoublePipelineData");
        put("Alg.Alias.KeyGenerator.KbkdfPipelineData", "KbkdfDoublePipelineData");
        put("Alg.Alias.KeyGenerator.KBKDF-Pipeline-Data", "KbkdfDoublePipelineData");
        put("Alg.Alias.KeyGenerator.SP800-108-KDF-Pipeline-Data", "KbkdfDoublePipelineData");
        put("Alg.Alias.KeyGenerator.SP800-108-Pipeline-Data", "KbkdfDoublePipelineData");
        put("Alg.Alias.KeyGenerator.PipelineKbkdf-Data", "KbkdfDoublePipelineData");

        /////////////////////////////////////////////////////////////
        // SecretKeyFactory
        /////////////////////////////////////////////////////////////
        put("SecretKeyFactory.GenericSecret", "org.mozilla.jss.provider.javax.crypto.JSSSecretKeyFactorySpi$GenericSecret");
        put("Alg.Alias.SecretKeyFactory.GENERIC_SECRET", "GenericSecret");
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
        put("SecretKeyFactory.HmacSHA256",
            "org.mozilla.jss.provider.javax.crypto.JSSSecretKeyFactorySpi$HmacSHA256");
        put("SecretKeyFactory.HmacSHA384",
            "org.mozilla.jss.provider.javax.crypto.JSSSecretKeyFactorySpi$HmacSHA384");
        put("SecretKeyFactory.HmacSHA512",
            "org.mozilla.jss.provider.javax.crypto.JSSSecretKeyFactorySpi$HmacSHA512");
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
        put("Mac.CmacAES", "org.mozilla.jss.provider.javax.crypto.JSSMacSpi$CmacAES");
        put("Alg.Alias.Mac.Hmac-SHA512", "HmacSHA512");
        put("Alg.Alias.Mac.SHA-1-HMAC", "HmacSHA1");
        put("Alg.Alias.Mac.SHA-256-HMAC", "HmacSHA256");
        put("Alg.Alias.Mac.SHA-384-HMAC", "HmacSHA384");
        put("Alg.Alias.Mac.SHA-512-HMAC", "HmacSHA512");
        put("Alg.Alias.Mac.AES-128-CMAC", "CmacAES");
        put("Alg.Alias.Mac.AES-192-CMAC", "CmacAES");
        put("Alg.Alias.Mac.AES-256-CMAC", "CmacAES");
        put("Alg.Alias.Mac.CmacAES128", "CmacAES");
        put("Alg.Alias.Mac.CmacAES192", "CmacAES");
        put("Alg.Alias.Mac.CmacAES256", "CmacAES");
        put("Alg.Alias.Mac.AES_CMAC", "CmacAES");
        put("Alg.Alias.Mac.CMAC_AES", "CmacAES");


        /////////////////////////////////////////////////////////////
        // KeyManagerFactory
        /////////////////////////////////////////////////////////////
        put("KeyManagerFactory.NssX509",
            "org.mozilla.jss.provider.javax.crypto.JSSKeyManagerFactory");
        put("Alg.Alias.KeyManagerFactory.SunX509", "NssX509");
        put("Alg.Alias.KeyManagerFactory.PKIX", "SunX509");


        /////////////////////////////////////////////////////////////
        // TrustManagerFactory
        /////////////////////////////////////////////////////////////
        put("TrustManagerFactory.NssX509",
            "org.mozilla.jss.provider.javax.crypto.JSSTrustManagerFactory");
        put("Alg.Alias.TrustManagerFactory.SunX509", "NssX509");
        put("Alg.Alias.TrustManagerFactory.PKIX", "NssX509");
        put("Alg.Alias.TrustManagerFactory.X509", "NssX509");
        put("Alg.Alias.TrustManagerFactory.X.509", "NssX509");

        /////////////////////////////////////////////////////////////
        // TLS
        /////////////////////////////////////////////////////////////
        if (ENABLE_JSSENGINE) {
            put("SSLContext.Default", "org.mozilla.jss.provider.javax.net.JSSContextSpi");
            put("SSLContext.SSL", "org.mozilla.jss.provider.javax.net.JSSContextSpi");
            put("SSLContext.TLS", "org.mozilla.jss.provider.javax.net.JSSContextSpi");
            put("SSLContext.TLSv1.1", "org.mozilla.jss.provider.javax.net.JSSContextSpi$TLSv11");
            put("SSLContext.TLSv1.2", "org.mozilla.jss.provider.javax.net.JSSContextSpi$TLSv12");
            put("SSLContext.TLSv1.3", "org.mozilla.jss.provider.javax.net.JSSContextSpi$TLSv13");
        }
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
