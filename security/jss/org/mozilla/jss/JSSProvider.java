/* 
 * The contents of this file are subject to the Mozilla Public
 * License Version 1.1 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of
 * the License at http://www.mozilla.org/MPL/
 * 
 * Software distributed under the License is distributed on an "AS
 * IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * rights and limitations under the License.
 * 
 * The Original Code is the Netscape Security Services for Java.
 * 
 * The Initial Developer of the Original Code is Netscape
 * Communications Corporation.  Portions created by Netscape are 
 * Copyright (C) 1998-2000 Netscape Communications Corporation.  All
 * Rights Reserved.
 * 
 * Contributor(s):
 * 
 * Alternatively, the contents of this file may be used under the
 * terms of the GNU General Public License Version 2 or later (the
 * "GPL"), in which case the provisions of the GPL are applicable 
 * instead of those above.  If you wish to allow use of your 
 * version of this file only under the terms of the GPL and not to
 * allow others to use your version of this file under the MPL,
 * indicate your decision by deleting the provisions above and
 * replace them with the notice and other provisions required by
 * the GPL.  If you do not delete the provisions above, a recipient
 * may use your version of this file under either the MPL or the
 * GPL.
 */
package org.mozilla.jss;

public final class JSSProvider extends java.security.Provider {

    public JSSProvider() {
        super("Mozilla-JSS", 3.2,
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
        put("Signature.MD2/RSA",
            "org.mozilla.jss.provider.java.security.JSSSignatureSpi$MD2RSA");
        put("Signature.SHA-1/RSA",
            "org.mozilla.jss.provider.java.security.JSSSignatureSpi$SHA1RSA");

        put("Alg.Alias.Signature.SHA1/RSA", "SHA-1/RSA");
        put("Alg.Alias.Signature.SHA1withRSA", "SHA-1/RSA");

        /////////////////////////////////////////////////////////////
        // Message Digesting
        /////////////////////////////////////////////////////////////

        put("MessageDigest.SHA-1",
                "org.mozilla.jss.provider.java.security.JSSMessageDigestSpi$SHA1");
        put("MessageDigest.MD2",
                "org.mozilla.jss.provider.java.security.JSSMessageDigestSpi$MD2");
        put("MessageDigest.MD5",
                "org.mozilla.jss.provider.java.security.JSSMessageDigestSpi$MD5");

        put("Alg.Alias.MessageDigest.SHA1", "SHA-1");
        put("Alg.Alias.MessageDigest.SHA", "SHA-1");

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

        /////////////////////////////////////////////////////////////
        // KeyFactory
        /////////////////////////////////////////////////////////////
        put("KeyFactory.RSA",
            "org.mozilla.jss.provider.java.security.KeyFactorySpi1_2");
        put("KeyFactory.DSA",
            "org.mozilla.jss.provider.java.security.KeyFactorySpi1_2");

        /////////////////////////////////////////////////////////////
        // KeyStore
        /////////////////////////////////////////////////////////////
        put("KeyStore.Mozilla-JSS",
            "org.mozilla.jss.provider.java.security.JSSKeyStoreSpi");

        /////////////////////////////////////////////////////////////
        // AlgorithmParameters
        /////////////////////////////////////////////////////////////
        put("AlgorithmParameters.IvAlgorithmParameters",
            "org.mozilla.jss.provider.java.security.IvAlgorithmParameters");

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
    }
}
