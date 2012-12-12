/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.tests;

import org.mozilla.jss.ssl.*;

/**
 * Holds immutable values for JSS Tests.
 *
 */
public interface Constants {

    /** Debug level for all tests */
    public static int debug_level = 1;

   public static final class cipher {
        int value; /* hex value */
        String name;
        cipher(int v, String n) {
            value = v;
            name = n;
        }
       
        /*
         * returns the string representation of the ciphersuite OR 
         * returns null if the ciphersuite is not found
         */
        public static final String cipherToString(int aCipher ) {
            
            for (int i = 0; i < Constants.jssCipherSuites.length; i++) {
                if (aCipher == Constants.jssCipherSuites[i].value) {
                    return Constants.jssCipherSuites[i].name;
                }
            }
            
            return null;
        }

        /*
         * returns the integer value of the ciphersuite OR 
         * returns -1 if the ciphersuite is not found.
         */
        public static final int stringToCipher(String sCipher ) {
            for (int i = 0; i < Constants.jssCipherSuites.length; i++) {
                if (sCipher.compareToIgnoreCase(
                        Constants.jssCipherSuites[i].name) == 0) {
                    return Constants.jssCipherSuites[i].value;
                }
            }
            
            return -1;
        }
        
    }
    
    /* cipherSuites Supported by JSS */
    public static final cipher jssCipherSuites[] = {
/*0 */  new cipher(SSLSocket.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"),
/*1 */  new cipher(SSLSocket.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"),
/*2 */  new cipher(SSLSocket.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA"),
/*3 */  new cipher(SSLSocket.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA, "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA"),
/*4 */  new cipher(SSLSocket.TLS_DHE_RSA_WITH_AES_256_CBC_SHA, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"),
/*5 */  new cipher(SSLSocket.TLS_DHE_DSS_WITH_AES_256_CBC_SHA, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA"),
/*6 */  new cipher(SSLSocket.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA"),
/*7 */  new cipher(SSLSocket.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA"),
/*8 */  new cipher(SSLSocket.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA"),
/*9 */  new cipher(SSLSocket.TLS_RSA_WITH_AES_256_CBC_SHA, "TLS_RSA_WITH_AES_256_CBC_SHA"),
/*10 */  new cipher(SSLSocket.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"),
/*11 */  new cipher(SSLSocket.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"),
/*12 */  new cipher(SSLSocket.TLS_ECDHE_RSA_WITH_RC4_128_SHA, "TLS_ECDHE_RSA_WITH_RC4_128_SHA"),
/*13 */  new cipher(SSLSocket.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"),
/*14 */  new cipher(SSLSocket.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA"),
/*15 */  new cipher(SSLSocket.TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA, "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA"),
/*16 */  new cipher(SSLSocket.TLS_DHE_DSS_WITH_RC4_128_SHA, "TLS_DHE_DSS_WITH_RC4_128_SHA"),
/*17 */  new cipher(SSLSocket.TLS_DHE_RSA_WITH_AES_128_CBC_SHA, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"),
/*18 */  new cipher(SSLSocket.TLS_DHE_DSS_WITH_AES_128_CBC_SHA, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA"),
/*19 */  new cipher(SSLSocket.TLS_ECDH_RSA_WITH_RC4_128_SHA, "TLS_ECDH_RSA_WITH_RC4_128_SHA"),
/*20 */  new cipher(SSLSocket.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA"),
/*21 */  new cipher(SSLSocket.TLS_ECDH_ECDSA_WITH_RC4_128_SHA, "TLS_ECDH_ECDSA_WITH_RC4_128_SHA"),
/*22 */  new cipher(SSLSocket.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA"),
/*23 */  new cipher(SSLSocket.TLS_RSA_WITH_SEED_CBC_SHA, "TLS_RSA_WITH_SEED_CBC_SHA"),
/*24 */  new cipher(SSLSocket.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA"),
/*25 */  new cipher(SSLSocket.SSL3_RSA_WITH_RC4_128_MD5, "SSL3_RSA_WITH_RC4_128_MD5"),
/*26 */  new cipher(SSLSocket.SSL3_RSA_WITH_RC4_128_SHA, "SSL3_RSA_WITH_RC4_128_SHA"),
/*27 */  new cipher(SSLSocket.TLS_RSA_WITH_AES_128_CBC_SHA, "TLS_RSA_WITH_AES_128_CBC_SHA"),
/*28 */  new cipher(SSLSocket.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA, "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"),
/*29 */  new cipher(SSLSocket.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"),
/*30 */  new cipher(SSLSocket.SSL3_DHE_RSA_WITH_3DES_EDE_CBC_SHA, "SSL3_DHE_RSA_WITH_3DES_EDE_CBC_SHA"),
/*31 */  new cipher(SSLSocket.SSL3_DHE_DSS_WITH_3DES_EDE_CBC_SHA, "SSL3_DHE_DSS_WITH_3DES_EDE_CBC_SHA"),
/*32 */  new cipher(SSLSocket.TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA, "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA"),
/*33 */  new cipher(SSLSocket.TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA, "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA"),
/*34 */  new cipher(SSLSocket.SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA, "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA"),
/*35 */  new cipher(SSLSocket.SSL3_RSA_WITH_3DES_EDE_CBC_SHA, "SSL3_RSA_WITH_3DES_EDE_CBC_SHA"),
/*36 */  new cipher(SSLSocket.SSL3_DHE_RSA_WITH_DES_CBC_SHA, "SSL3_DHE_RSA_WITH_DES_CBC_SHA"),
/*37 */  new cipher(SSLSocket.SSL3_DHE_DSS_WITH_DES_CBC_SHA, "SSL3_DHE_DSS_WITH_DES_CBC_SHA"),
/*38 */  new cipher(SSLSocket.SSL_RSA_FIPS_WITH_DES_CBC_SHA, "SSL_RSA_FIPS_WITH_DES_CBC_SHA"),
/*39 */  new cipher(SSLSocket.SSL3_RSA_WITH_DES_CBC_SHA, "SSL3_RSA_WITH_DES_CBC_SHA"),
/*40 */  new cipher(SSLSocket.TLS_RSA_EXPORT1024_WITH_RC4_56_SHA, "TLS_RSA_EXPORT1024_WITH_RC4_56_SHA"),
/*41 */  new cipher(SSLSocket.TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA, "TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA"),
/*42 */  new cipher(SSLSocket.SSL3_RSA_EXPORT_WITH_RC4_40_MD5, "SSL3_RSA_EXPORT_WITH_RC4_40_MD5"),
/*43 */  new cipher(SSLSocket.SSL3_RSA_EXPORT_WITH_RC2_CBC_40_MD5, "SSL3_RSA_EXPORT_WITH_RC2_CBC_40_MD5"),
/*44 */  new cipher(SSLSocket.TLS_ECDHE_ECDSA_WITH_NULL_SHA, "TLS_ECDHE_ECDSA_WITH_NULL_SHA"),
/*45 */  new cipher(SSLSocket.TLS_ECDHE_RSA_WITH_NULL_SHA, "TLS_ECDHE_RSA_WITH_NULL_SHA"),
/*46 */  new cipher(SSLSocket.TLS_ECDH_RSA_WITH_NULL_SHA, "TLS_ECDH_RSA_WITH_NULL_SHA"),
/*47 */  new cipher(SSLSocket.TLS_ECDH_ECDSA_WITH_NULL_SHA, "TLS_ECDH_ECDSA_WITH_NULL_SHA"),
/*48 */  new cipher(SSLSocket.SSL3_RSA_WITH_NULL_SHA, "SSL3_RSA_WITH_NULL_SHA"),
/*49 */  new cipher(SSLSocket.SSL3_RSA_WITH_NULL_MD5, "SSL3_RSA_WITH_NULL_MD5"),
/**
/* SSL2 ciphersuites are here for legacy purposes.  
 * you should call SSLSocket.enableSSL2Default(false) during your setup. 
 * to disable all SSL2 ciphersuites.  
 **/ 
/*50 */  new cipher(SSLSocket.SSL2_RC4_128_WITH_MD5, "SSL2_RC4_128_WITH_MD5"),
/*51 */  new cipher(SSLSocket.SSL2_RC2_128_CBC_WITH_MD5, "SSL2_RC2_128_CBC_WITH_MD5"),
/*52 */  new cipher(SSLSocket.SSL2_DES_192_EDE3_CBC_WITH_MD5, "SSL2_DES_192_EDE3_CBC_WITH_MD5"),
/*53 */  new cipher(SSLSocket.SSL2_DES_64_CBC_WITH_MD5, "SSL2_DES_64_CBC_WITH_MD5"),
/*54 */  new cipher(SSLSocket.SSL2_RC4_128_EXPORT40_WITH_MD5, "SSL2_RC4_128_EXPORT40_WITH_MD5"),
/*55 */  new cipher(SSLSocket.SSL2_RC2_128_CBC_EXPORT40_WITH_MD5, "SSL2_RC2_128_CBC_EXPORT40_WITH_MD5")
    };
    
    /** Cipher supported by JSSE (JDK 1.5.x) */
    public static String [] sslciphersarray_jdk150 = {
        // These ciphers must always pass
        "SSL_RSA_WITH_RC4_128_MD5",
        "SSL_RSA_WITH_RC4_128_SHA",
        "TLS_RSA_WITH_AES_128_CBC_SHA",
        "SSL_RSA_WITH_DES_CBC_SHA",
        "SSL_RSA_WITH_3DES_EDE_CBC_SHA",
        "SSL_RSA_EXPORT_WITH_RC4_40_MD5",
        "SSL_RSA_WITH_NULL_MD5",
    };
    
    /** Cipher supported by JSSE (JDK 1.4.x) */
    public static String [] sslciphersarray_jdk142 = {
        "SSL_RSA_WITH_RC4_128_MD5",
        "SSL_RSA_WITH_RC4_128_SHA",
        "TLS_RSA_WITH_AES_128_CBC_SHA",
        "SSL_RSA_WITH_DES_CBC_SHA",
        "SSL_RSA_WITH_3DES_EDE_CBC_SHA",
        "SSL_RSA_EXPORT_WITH_RC4_40_MD5",
        "SSL_RSA_WITH_NULL_MD5",
    };
}
