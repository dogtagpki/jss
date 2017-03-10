/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.tests;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import org.mozilla.jss.CertDatabaseException;
import org.mozilla.jss.KeyDatabaseException;
import org.mozilla.jss.crypto.*;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.util.IncorrectPasswordException;
import org.mozilla.jss.util.PasswordCallback;
import java.security.Provider;
import java.security.Security;

import java.security.AlgorithmParameters;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.spec.RC2ParameterSpec;

import javax.crypto.KeyGenerator;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.SecureRandom;

/**
 *
 */
public class JCASymKeyGen {
    static final String MOZ_PROVIDER_NAME = "Mozilla-JSS";
    byte[] plainText     = "Firefox   rules!Firefox   rules!Firefox   rules!Firefox   rules!Firefox   rules!".getBytes();
    byte[] plainTextPad  = "Thunderbird rules!Thunderbird rules!Thunderbird rules!Thunderbird rules!Thunderbird rules!".getBytes();
    byte[] plainTextB    = "NSPR   NSS  JSS!NSPR   NSS  JSS!NSPR   NSS  JSS!".getBytes();
    byte[] plainTextPadB = "Use Firefox and Thunderbird!".getBytes();

    static boolean bFipsMode = false;
    /**
     * Default constructor
     */
    public JCASymKeyGen( String certDbLoc, String passwdFile) {
        try {
            CryptoManager.initialize(certDbLoc);
            CryptoManager cm  = CryptoManager.getInstance();
            CryptoToken token = cm.getInternalCryptoToken();
            if (cm.FIPSEnabled()) {
                try {
                    bFipsMode=true;
                    PasswordCallback cb = new FilePasswordCallback(passwdFile);
                    token.login(cb);
                    System.out.println("Logged in");
                } catch (IncorrectPasswordException ex) {
                    ex.printStackTrace();
                    System.exit(1);
                } catch (TokenException ex) {
                    ex.printStackTrace();
                    System.exit(1);
                } catch (IOException ex) {
                    ex.printStackTrace();
                    System.exit(1);
                }
            }
        } catch (AlreadyInitializedException ex) {
            ex.printStackTrace();
            System.exit(1);
        } catch (CertDatabaseException ex) {
            ex.printStackTrace();
            System.exit(1);
        } catch (CryptoManager.NotInitializedException ex) {
            ex.printStackTrace();
            System.exit(1);
        } catch (GeneralSecurityException ex) {
            ex.printStackTrace();
            System.exit(1);
        } catch (KeyDatabaseException ex) {
            ex.printStackTrace();
            System.exit(1);
        }
    }
    /**
     * 
     * @param keyType
     * @param provider
     * @return javax.crypto.SecretKey key
     */
    public javax.crypto.SecretKey genSecretKey(String keyType, String provider){
        javax.crypto.SecretKey key = null;
        javax.crypto.KeyGenerator kg = null;
        try {
            
            kg = KeyGenerator.getInstance(keyType,
                    provider);
            if (keyType.equals("AES") || keyType.equals("RC2")) {
                kg.init(128); //JDK 1.4 and 1.5 only supports 128 keys for AES
            }
            
            System.out.println("Key " + keyType + " generation done by "
                    + kg.getProvider().toString());
            key = kg.generateKey();
            if( !checkAlgorithm(key, keyType) ) {
                throw new Exception("Error: " + key.getAlgorithm() +
                        "  algorithm");
            }
            //System.out.println("The length of the generated key in bits: " +
            //    (key.getEncoded().length * 8) +
            //    " " + key.getAlgorithm() );
        } catch (NoSuchProviderException ex) {
            ex.printStackTrace();
        } catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return key;
    }
    
    /**
     * 
     * @param keyType 
     * @param provider 
     * @return javax.crypto.SecretKey key
     */
    public javax.crypto.SecretKey genPBESecretKey(String keyType,
            String provider){
        javax.crypto.SecretKey key = null;
        javax.crypto.SecretKeyFactory kf = null;
        try {
            char[] pw = "thunderbird".toCharArray();
            byte[] salt = new byte[8];
            SecureRandom random = SecureRandom.getInstance("pkcs11prng",
                    MOZ_PROVIDER_NAME);
            random.nextBytes(salt);
            int iterationCount = 2;

            kf = SecretKeyFactory.getInstance(keyType,
                    provider);
            PBEKeySpec keySpec = new PBEKeySpec(pw, salt, iterationCount);
            key = (SecretKeyFacade) kf.generateSecret(keySpec);

            //todo this should work as well
            //PBEKeySpec pbeKeySpec = new PBEKeySpec(pw));
            // key = kf.generateSecret(pbeKeySpec);
            System.out.println("Key " + keyType + " generation done by "
                    + kf.getProvider().toString());
            if (!bFipsMode) {
                System.out.println("The length of the generated key in bits: " +
                (key.getEncoded().length * 8) +
                " " + key.getAlgorithm() );
            }
        } catch (NoSuchProviderException ex) {
            ex.printStackTrace();
        } catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return key;
    }
    
    /**
     *
     * @param sKey
     * @param algFamily
     * @param algType
     * @param providerForEncrypt
     * @param providerForDecrypt
     */
    public void testCipher(javax.crypto.SecretKey sKey, String algFamily,
            String algType, String providerForEncrypt, String providerForDecrypt)
            throws Exception {
        try {
            
            // if no padding is used plainText needs to be fixed length
            // block divisable by 8 bytes
            byte[] plaintext = plainText;
            if (algType.endsWith("PKCS5Padding")) {
                plaintext = plainTextPad;
            }
            
            //encypt
            Cipher cipher = Cipher.getInstance(algType, providerForEncrypt);
            AlgorithmParameters ap = null;
            byte[] encodedAlgParams = null;
            AlgorithmParameterSpec RC2ParSpec = null;
            
            if (algFamily.compareToIgnoreCase("RC2")==0) {
                //JDK 1.4 requires you to pass in generated algorithm
                //parameters for RC2 (JDK 1.5 does not).
                byte[] iv = new byte[8];
                SecureRandom random = SecureRandom.getInstance("pkcs11prng",
                        MOZ_PROVIDER_NAME);
                random.nextBytes(iv);
                RC2ParSpec = new RC2ParameterSpec(128, iv);
                cipher.init(Cipher.ENCRYPT_MODE, sKey, RC2ParSpec);

            } else {
                cipher.init(Cipher.ENCRYPT_MODE, sKey);
                //generate the algorithm Parameters; they need to be
                //the same for encrypt/decrypt if they are needed.
                ap = cipher.getParameters();
                if (ap != null) {
                    //get parameters to store away as example.
                    encodedAlgParams = ap.getEncoded();
                }
            }


            //System.out.print(plaintext.length + " plaintext size " +
            //        providerForEncrypt + " encrypt outputsize: " +
            //        cipher.getOutputSize(plaintext.length));
            byte[] ciphertext =
                    new byte[cipher.getOutputSize(plaintext.length)];
            int cLen = cipher.update(plaintext, 0, plaintext.length,
                    ciphertext, 0);
            cLen += cipher.doFinal(ciphertext, cLen);

            //decrypt
            cipher = Cipher.getInstance(algType, providerForDecrypt);
            if (encodedAlgParams == null)
                if (RC2ParSpec != null)
                    // JDK 1.4 RC2
                    cipher.init(Cipher.DECRYPT_MODE, sKey, RC2ParSpec);
                else
                    cipher.init(Cipher.DECRYPT_MODE, sKey);
            else {
                //retrieve the algorithmParameters from the encoded array
                AlgorithmParameters aps =
                        AlgorithmParameters.getInstance(algFamily);
                aps.init(encodedAlgParams);
                cipher.init(Cipher.DECRYPT_MODE, sKey, aps);
            }

            byte[] recovered = new byte[cLen];
            int rLen = cipher.update(ciphertext, 0, cLen, recovered, 0);
            rLen += cipher.doFinal(recovered, rLen);

            //ensure the recovered bytes equals the orginal plaintext
            boolean isEqual = true;
            for (int i = 0; i < plaintext.length; i++) {
                if (plaintext[i] != recovered[i]) {
                    isEqual = false;
                    break;
                }
            }

            if (isEqual) {
                //System.out.println(providerForEncrypt + " encrypted & " +
                //       providerForDecrypt + " decrypted using " +
                //       algType + " successful.");
            } else {
                throw new Exception("ERROR: " + providerForEncrypt +
                        " and " + providerForDecrypt + " failed for "
                        + algType );
            }
        } catch (InvalidKeyException ex) {
            ex.printStackTrace();
        } catch (javax.crypto.BadPaddingException ex) {
            ex.printStackTrace();
        } catch (NoSuchProviderException ex) {
            ex.printStackTrace();
        } catch (javax.crypto.NoSuchPaddingException ex) {
            ex.printStackTrace();
        } catch (javax.crypto.IllegalBlockSizeException ex) {
            ex.printStackTrace();
        } catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace();
        }
    }
    /**
     *
     * @param sKey
     * @param algFamily
     * @param algType
     * @param providerForEncrypt
     * @param providerForDecrypt
     */
    public void testMultiPartCipher(javax.crypto.SecretKey sKey, String algFamily,
            String algType, String providerForEncrypt, String providerForDecrypt)
            throws Exception {
        try {
            
            // if no padding is used plainText needs to be fixed length
            // block divisable by 8 bytes
            byte[] plaintext = plainText;
            byte[] plaintextB = plainTextB;
            if (algType.endsWith("PKCS5Padding")) {
                plaintext = plainTextPad;
                plaintextB = plainTextPadB;
            }

            //encypt
            Cipher cipher = Cipher.getInstance(algType, providerForEncrypt);
            AlgorithmParameters ap = null;
            byte[] encodedAlgParams = null;
            AlgorithmParameterSpec RC2ParSpec = null;

            if (algFamily.compareToIgnoreCase("RC2")==0) {
                //JDK 1.4 requires you to pass in generated algorithm
                //parameters for RC2 (JDK 1.5 does not).
                byte[] iv = new byte[8];
                SecureRandom random = SecureRandom.getInstance("pkcs11prng",
                        MOZ_PROVIDER_NAME);
                random.nextBytes(iv);
                RC2ParSpec = new RC2ParameterSpec(128, iv);
                cipher.init(Cipher.ENCRYPT_MODE, sKey, RC2ParSpec);

            } else {
                cipher.init(Cipher.ENCRYPT_MODE, sKey);
                //generate the algorithm Parameters; they need to be
                //the same for encrypt/decrypt if they are needed.
                ap = cipher.getParameters();
                if (ap != null) {
                    //get parameters to store away as example.
                    encodedAlgParams = ap.getEncoded();
                }
            }

            byte[] ciphertext =
                new byte[(cipher.getOutputSize(plaintext.length +
                    plaintextB.length))];
            int cLen = cipher.update(plaintext, 0, plaintext.length,
                    ciphertext, 0);
            cLen += cipher.update(plaintextB, 0, plaintextB.length,
                    ciphertext, cLen);
            cLen += cipher.doFinal(ciphertext, cLen);

            //decrypt
            cipher = Cipher.getInstance(algType, providerForDecrypt);
            if (encodedAlgParams == null)
                if (RC2ParSpec != null)
                    // JDK 1.4 RC2
                    cipher.init(Cipher.DECRYPT_MODE, sKey, RC2ParSpec);
                else
                    cipher.init(Cipher.DECRYPT_MODE, sKey);
            else {
                //retrieve the algorithmParameters from the encoded array
                AlgorithmParameters aps =
                        AlgorithmParameters.getInstance(algFamily);
                aps.init(encodedAlgParams);
                cipher.init(Cipher.DECRYPT_MODE, sKey, aps);
            }

            byte[] recovered = new byte[cLen];
            int rLen = cipher.update(ciphertext, 0, cLen, recovered, 0);
            rLen += cipher.doFinal(recovered, rLen);

            //ensure the recovered bytes equals the original plaintext
            boolean isEqual = true;
            for (int i = 0; i < plaintext.length; i++) {
                if (i<plaintext.length) {
                    if (plaintext[i] != recovered[i]) {
                        isEqual = false;
                        break;
                    }
                } else {
                    if (plaintextB[i - plainText.length] == recovered[i] ) {
                        isEqual = false;
                        break;
                    }
                }
            }

            if (isEqual) {
                //System.out.println(providerForEncrypt + " encrypted & " +
                //       providerForDecrypt + " decrypted using " +
                //       algType + " successful.");
            } else {
                throw new Exception("ERROR: " + providerForEncrypt +
                        " and " + providerForDecrypt + " failed for "
                        + algType );
            }
        } catch (InvalidKeyException ex) {
            ex.printStackTrace();
        } catch (javax.crypto.BadPaddingException ex) {
            ex.printStackTrace();
        } catch (NoSuchProviderException ex) {
            ex.printStackTrace();
        } catch (javax.crypto.NoSuchPaddingException ex) {
            ex.printStackTrace();
        } catch (javax.crypto.IllegalBlockSizeException ex) {
            ex.printStackTrace();
        } catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace();
        }
    }

    public static void main(String args[]) {

        String certDbLoc             = ".";
        String passwdFile            = null;
        // Mozilla supported symmetric key ciphers and algorithms
        // Note JCE supports algorithm/ECB/PKCS5Padding and JSS does
        // not support algorithms in ECB mode with PKCS5Padding
        String [][] symKeyTable = {
            {"DES",  "DES/ECB/NoPadding", "DES/CBC/PKCS5Padding",
                     "DES/CBC/NoPadding" },
            {"DESede", "DESede/ECB/NoPadding", "DESede/CBC/PKCS5Padding",
                              "DESede/CBC/NoPadding" },
            {"AES", "AES/ECB/NoPadding",  "AES/CBC/NoPadding",
                                 "AES/CBC/PKCS5Padding"},
            {"RC2", "RC2/CBC/NoPadding", "RC2/CBC/PKCS5Padding"},
            //{"RC4", "RC4"}, todo
            //{"PBAHmacSHA1"},
            {"PBEWithMD5AndDES", "DES/ECB/NoPadding"},
            //todo "DES/CBC/PKCS5Padding",  "DES/CBC/NoPadding" },
            {"PBEWithSHA1AndDES"},
            {"PBEWithSHA1AndDESede", "DESede/ECB/NoPadding"},
            //{"PBEWithSHA1And128RC4"}, todo
        };



        if ( args.length <= 2 ) {
            certDbLoc  = args[0];
            if (args.length == 2) {
                passwdFile = args[1];
            }
        } else {
            System.out.println(
                    "USAGE: java org.mozilla.jss.tests.JCASymKeyGen" +
                    " <certDbPath> [passwordFile]");
            System.out.println("password file only required if in " +
                                "FIPSMODE.");
            System.out.println("FIPSMODE requires Java 1.6 or higher!");
            System.exit(1);
        }

        //If the IBMJCE provider exists tests with it otherwise
        //use the SunJCE provider.
        String otherProvider = new String("IBMJCE");
        Provider p = null;
        p = Security.getProvider(otherProvider);
        if (p == null) {
            otherProvider = new String("SunJCE");
            p = Security.getProvider(otherProvider);
            if (p == null){
                System.out.println("unable to find IBMJCE or SunJCE providers");
                System.exit(1);
            }
        }
        JCASymKeyGen skg = new JCASymKeyGen(certDbLoc, passwdFile);
        System.out.println(otherProvider + ": " + p.getInfo());
        p = Security.getProvider(MOZ_PROVIDER_NAME);
        System.out.println(MOZ_PROVIDER_NAME + ": " + p.getInfo());

        javax.crypto.SecretKey mozKey = null;

        try {

            for (int i = 0 ; i < symKeyTable.length; i++) {
                try {
                    //generate the key using mozilla
                    if (symKeyTable[i][0].startsWith("PBE") == true) {
                        mozKey = skg.genPBESecretKey(symKeyTable[i][0],
                                MOZ_PROVIDER_NAME);
                    } else {
                        mozKey = skg.genSecretKey(symKeyTable[i][0],
                                MOZ_PROVIDER_NAME);
                    }
                } catch(Exception e) {
                    System.out.println("unable to generate key: " +
                            symKeyTable[i][0] + " " + e.getMessage());
                }
                //test the cipher algorithms for this keyType
                for (int a = 1 ;  a < symKeyTable[i].length; a++){
                    //encrypt/decrypt with Mozilla Provider

                    skg.testCipher(mozKey, symKeyTable[i][0], symKeyTable[i][a],
                            MOZ_PROVIDER_NAME, MOZ_PROVIDER_NAME);
                    skg.testMultiPartCipher(mozKey, symKeyTable[i][0],
                        symKeyTable[i][a],
                        MOZ_PROVIDER_NAME, MOZ_PROVIDER_NAME);

                    try {
                        //check to see if the otherProvider we are testing
                        //against supports the algorithm.
                        Cipher cipher = Cipher.getInstance(symKeyTable[i][a],
                                otherProvider);
                    } catch (Exception e) {
                        System.out.println(MOZ_PROVIDER_NAME + " only supports "
                                + symKeyTable[i][a]);
                        //therefore don't try comparison
                        continue;
                    }
                    //in FIPSMODE you can only use the Mozilla Provider
                    if (!bFipsMode) {
                        //encrypt with Mozilla, and Decrypt with otherProvider
                        skg.testCipher(mozKey, symKeyTable[i][0],
                            symKeyTable[i][a],
                            MOZ_PROVIDER_NAME, otherProvider);
                        skg.testMultiPartCipher(mozKey, symKeyTable[i][0],
                            symKeyTable[i][a],
                            MOZ_PROVIDER_NAME, otherProvider);


                        //encrypt with otherProvider and decrypt with Mozilla
                        skg.testCipher(mozKey, symKeyTable[i][0],
                            symKeyTable[i][a],
                            otherProvider, MOZ_PROVIDER_NAME);
                        skg.testMultiPartCipher(mozKey, symKeyTable[i][0],
                            symKeyTable[i][a],
                            otherProvider, MOZ_PROVIDER_NAME);

                        System.out.println(MOZ_PROVIDER_NAME + " and  " +
                            otherProvider + " tested " + symKeyTable[i][a]);
                    }
                }
            }
        } catch(Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
        //end of main
        System.exit(0);
    }

    /**
     * Validate if the key algorithm of a given SecretKey
     * is the same as expected.
     * @param SecretKey k
     * @param String algorithm
     * @return boolean status
     */
    private boolean checkAlgorithm(SecretKey k, String alg) {
        boolean status = false;
        if( k.getAlgorithm().equals(alg) ) {
            status = true;
        }
        return status;
    }

    /**
     * Validate if the key length of a given SecretKey
     * is the same as expected.
     * @param SecretKey k
     * @param int key length
     * @return boolean status
     */
    private boolean checkKeyLength(SecretKey k, int len) {
        boolean status = false;
        byte[] keyData = k.getEncoded();
        if( keyData.length == len ) {
            status = true;
        }
        return status;
    }
    /**
     * Turns array of bytes into string
     *
     * @param buf Array of bytes to convert to hex string
     * @return Generated hex string
     */
    private String asHex(byte buf[]) {
        StringBuffer strbuf = new StringBuffer(buf.length * 2);
        int i;

        for (i = 0; i < buf.length; i++) {
            if (((int) buf[i] & 0xff) < 0x10)
                strbuf.append("0");
            strbuf.append(Long.toString((int) buf[i] & 0xff, 16));
        }
        return strbuf.toString();
    }
}
