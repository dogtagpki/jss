/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss.tests;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import org.mozilla.jss.CryptoManager.NotInitializedException;
import org.mozilla.jss.crypto.SecretKeyFacade;
import org.mozilla.jss.crypto.AlreadyInitializedException;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.TokenException;
import javax.crypto.SecretKey;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import org.mozilla.jss.CertDatabaseException;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.KeyDatabaseException;
import org.mozilla.jss.util.IncorrectPasswordException;
import org.mozilla.jss.util.PasswordCallback;

/**
 * Test Mozilla-JSS provider key wrap/unwrap
 *
 * JSS currently needs to compile with JDK 1.4.2.x
 *
 * This program tests wrapping/unwrapping on symmetric keys.
 * unwraping of private keys is not available at this time see
 * https://bugzilla.mozilla.org/show_bug.cgi?id=135328
 *
 */
public class JCAKeyWrap {

    protected static final String MOZ_PROVIDER_NAME = "Mozilla-JSS";

    public static void main(String args[]) {

        if (args.length != 2) {
            usage();
            System.exit(1);
        }

        String dbdir = args[0];
        String passwdfile = args[1];
        try {

            JCAKeyWrap keyWrap = new JCAKeyWrap(dbdir, passwdfile);
            //If the IBMJCE provider exists tests with it otherwise
            //use the SunJCE provider.
            String otherProvider = new String("IBMJCE");
            String otherRSAProvider = new String("IBMJCE");
            Provider p = null;
            p = Security.getProvider(otherProvider);
            if (p == null) {
                otherProvider = new String("SunJCE");
                otherRSAProvider = new String("SunRsaSign");
                p = Security.getProvider(otherProvider);
                if (p == null) {
                    System.out.println("unable to find IBMJCE or SunJCE " +
                            "providers");

                    Provider[] providers = Security.getProviders();
                    for (int i = 0; i < providers.length; i++) {
                        System.out.println("Provider " + i + ": " +
                                providers[i].getName());
                    }
                    System.exit(1);
                }
            }

            // Generate an RSA keypair
            KeyPairGenerator kpgen;
            kpgen = KeyPairGenerator.getInstance("RSA", MOZ_PROVIDER_NAME);
            kpgen.initialize(1024);
            KeyPair rsaKeyPairNSS = kpgen.generateKeyPair();

            kpgen = KeyPairGenerator.getInstance("RSA", otherRSAProvider);
            kpgen.initialize(1024);
            KeyPair rsaKeyPairOtherProvider = kpgen.generateKeyPair();

            javax.crypto.SecretKey tripleDESKey;
            KeyGenerator keyGen = KeyGenerator.getInstance("DESede",
                    MOZ_PROVIDER_NAME);

            tripleDESKey = keyGen.generateKey();

            keyWrap.wrapSymetricKeyWithRSA(tripleDESKey, rsaKeyPairNSS,
                    MOZ_PROVIDER_NAME, MOZ_PROVIDER_NAME);

            if (!keyWrap.isBFipsMode()) {
                keyWrap.wrapSymetricKeyWithRSA(tripleDESKey, rsaKeyPairNSS,
                        MOZ_PROVIDER_NAME, otherProvider);
            }

            keyGen = KeyGenerator.getInstance("AES",
                    MOZ_PROVIDER_NAME);
            javax.crypto.SecretKey aesKeyToWrap;
            keyGen.init(128);
            aesKeyToWrap = keyGen.generateKey();
            keyGen = KeyGenerator.getInstance("AES", MOZ_PROVIDER_NAME);

            int AESKeySize[] = {128, 192, 256};

            for (int k = 0; k < AESKeySize.length; k++) {
                //create AES key
                javax.crypto.SecretKey aesKey;
                keyGen.init(AESKeySize[k]);
                aesKey = keyGen.generateKey();
                keyGen = KeyGenerator.getInstance("AES", MOZ_PROVIDER_NAME);
                int keyStrength =
                        (((SecretKeyFacade) aesKey).key.getStrength());

                //JDK 1.4 and 1.5 only supports 128 keys for AES
                //therefore only do comparison testing of providers with
                //128 key strength
                if (keyStrength == 128 && !keyWrap.isBFipsMode()) {
                    keyWrap.wrapSymetricKey(tripleDESKey,
                            "AES/CBC/PKCS5Padding", aesKey,
                            MOZ_PROVIDER_NAME, otherProvider);
                    keyWrap.wrapSymetricKey(aesKeyToWrap,
                            "AES/CBC/PKCS5Padding", aesKey,
                            MOZ_PROVIDER_NAME, otherProvider);
                    keyWrap.wrapSymetricKeyWithRSA(aesKey, rsaKeyPairNSS,
                            MOZ_PROVIDER_NAME, otherProvider);
                } else {
                    keyWrap.wrapSymetricKey(tripleDESKey,
                            "AES/CBC/PKCS5Padding", aesKey);
                    keyWrap.wrapSymetricKey(aesKeyToWrap,
                            "AES/CBC/PKCS5Padding", aesKey);
                    keyWrap.wrapSymetricKeyWithRSA(aesKey, rsaKeyPairNSS);
                }
                aesKeyToWrap = aesKey;
            }

        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }

        System.exit(0);
    }

    /**
     *
     */
    public static void usage() {
        System.out.println(
                "Usage: java org.mozilla.jss.tests.JCAKeyWrap " +
                "<dbdir> <passwordFile>");
    }
    protected boolean bFipsMode = false;
    protected byte[] plainText = "Firefox   rules!Firefox   rules!Firefox   rules!Firefox   rules!Firefox   rules!".getBytes();
    protected byte[] plainTextPad = "Thunderbird rules!Thunderbird rules!Thunderbird rules!Thunderbird rules!Thunderbird rules!".getBytes();

    /**
     * Default constructor to initialize Mozilla-JSS
     * @param certDbLoc
     * @param passwdFile
     */
    public JCAKeyWrap(String certDbLoc, String passwdFile) {
        try {
            CryptoManager.initialize(certDbLoc);
            CryptoManager cm = CryptoManager.getInstance();
            CryptoToken token = cm.getInternalKeyStorageToken();
            PasswordCallback cb = new FilePasswordCallback(passwdFile);
            token.login(cb);
            if (cm.FIPSEnabled()) {
                bFipsMode = true;
                System.out.println("in Fipsmode.");
            }
        } catch (IOException ex) {
            ex.printStackTrace();
            System.exit(1);
        } catch (KeyDatabaseException ex) {
            ex.printStackTrace();
            System.exit(1);
        } catch (CertDatabaseException ex) {
            ex.printStackTrace();
            System.exit(1);
        } catch (AlreadyInitializedException ex) {
            ex.printStackTrace();
            System.exit(1);
        } catch (GeneralSecurityException ex) {
            ex.printStackTrace();
            System.exit(1);
        } catch (IncorrectPasswordException ex) {
            ex.printStackTrace();
            System.exit(1);
        } catch (TokenException ex) {
            ex.printStackTrace();
            System.exit(1);
        } catch (NotInitializedException ex) {
            ex.printStackTrace();
            System.exit(1);
        }

    }

    /**
     *
     * @return true when in FIPS mode false otherwise
     */
    public boolean isBFipsMode() {
        return bFipsMode;
    }

    /**
     * Randomly selects a cipher transformation "algorithm/mode/padding".
     * @param symKeyType
     * @return a cipher transformation "algorithm/mode/padding"
     * @throws Exception
     */
    public String testCipher(String symKeyType)
            throws Exception {
        String testCipher;
        String[] cipherDESede = {"DESede/ECB/NoPadding",
            "DESede/CBC/PKCS5Padding",
            "DESede/CBC/NoPadding"};
        String[] cipherAES = {"AES/ECB/NoPadding", "AES/CBC/NoPadding",
            "AES/CBC/PKCS5Padding"};

        SecureRandom r = SecureRandom.getInstance("pkcs11prng",
                MOZ_PROVIDER_NAME);

        if (symKeyType.equalsIgnoreCase("AES")) {
            return cipherAES[r.nextInt(cipherAES.length)];
        } else if (symKeyType.equalsIgnoreCase("DESede")) {
            return cipherDESede[r.nextInt(cipherDESede.length)];
        } else {
            throw new Exception("no support for " + symKeyType);
        }

    }

    /**
     *
     * both providers are Mozilla-JSS
     *
     * @param symKey
     * @param keyPair
     * @throws Exception
     */
    public void wrapSymetricKeyWithRSA(Key symKey,
            KeyPair keyPair) throws Exception {

        wrapSymetricKeyWithRSA(symKey, keyPair,
                MOZ_PROVIDER_NAME, MOZ_PROVIDER_NAME);
    }

    /**
     *
     * @param symKey
     * @param keyPair
     * @param providerA
     * @param providerB
     * @throws Exception
     */
    public void wrapSymetricKeyWithRSA(
            Key symKey, KeyPair keyPair,
            String providerA, String providerB) throws Exception {
        try {

            String symKeyType = new String(symKey.getAlgorithm());

            System.out.print("Wrap " + symKeyType + " " +
                    ((SecretKeyFacade) symKey).key.getStrength() +
                    " with RSA. ");

            // wrap key
            Cipher cipher = Cipher.getInstance("RSA", providerA);
            cipher.init(Cipher.WRAP_MODE, keyPair.getPublic());
            byte[] wrappedData = cipher.wrap(symKey);

            // unwrap key
            cipher = Cipher.getInstance("RSA", providerA);
            cipher.init(Cipher.UNWRAP_MODE, keyPair.getPrivate());
            SecretKey unwrappedKey =
                    (javax.crypto.SecretKey) cipher.unwrap(wrappedData,
                    symKeyType, Cipher.SECRET_KEY);

            testKeys(symKey, unwrappedKey, providerA, providerB);

        } catch (BadPaddingException ex) {
            ex.printStackTrace();
            System.exit(1);
        } catch (UnsupportedEncodingException ex) {
            ex.printStackTrace();
            System.exit(1);
        } catch (IllegalBlockSizeException ex) {
            ex.printStackTrace();
            System.exit(1);
        } catch (InvalidKeyException ex) {
            ex.printStackTrace();
            System.exit(1);
        } catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace();
            System.exit(1);
        } catch (NoSuchPaddingException ex) {
            ex.printStackTrace();
            System.exit(1);
        }
    }

    /**
     * both providers used will be Mozilla-JSS
     *
     * @param symKey
     * @param wrapperAlg
     * @param wrapperKey
     * @throws Exception
     */
    public void wrapSymetricKey(Key symKey, String wrapperAlg,
            Key wrapperKey) throws Exception {

        wrapSymetricKey(symKey, wrapperAlg, wrapperKey,
                MOZ_PROVIDER_NAME, MOZ_PROVIDER_NAME);
    }

    /**
     * compare two keys
     *
     * @param key1
     * @param key2
     * @return true if equal false otherwise
     */
    static boolean keysEqual(Key key1, Key key2) {
        if (key1.equals(key2)) {
            return true;
        }
        if (Arrays.equals(key1.getEncoded(), key2.getEncoded())) {
            return true;
        }

        return false;
    }

    /**
     *
     * @param keyA
     * @param keyB
     * @param providerA
     * @param providerB
     * @throws java.lang.Exception
     */
    protected void testKeys(Key keyA, Key keyB, String providerA,
            String providerB) throws Exception {
        //ensure keys are equal
        if (bFipsMode) {
            //bFipsMode providerA and providerB mozilla-JSS
            //Keys are not extractable so just check key length
            if (((SecretKeyFacade) keyA).key.getStrength() !=
                    ((SecretKeyFacade) keyB).key.getStrength()) {
                throw new Exception("unwrapped key strength does not " +
                        "match orginal");
            }
        } else if (!keysEqual(keyA, keyB)) {
            throw new Exception("unwrapped key " +
                    "does not match original");
        }

        //As an extra test encrypt with keyA using ProviderA
        //and decrypt with with keyB using ProviderB

        String cipherAlg = testCipher(keyA.getAlgorithm());
        System.out.println("Test " + cipherAlg + " encrypt with " +
                providerA + " decrypt " + providerB);

        // if no padding is used plainText needs to be fixed length
        // block divisable by 8 bytes
        byte[] plaintext = plainText;
        if (cipherAlg.endsWith("PKCS5Padding")) {
            plaintext = plainTextPad;
        }

        //encrypt some text as a test with the key to be wrap
        Cipher cipher = Cipher.getInstance(cipherAlg, providerA);
        cipher.init(Cipher.ENCRYPT_MODE, keyA);

        byte[] encryptedText = cipher.doFinal(plaintext);

        //generate the algorithm Parameters; they need to be
        //the same for encrypt/decrypt if they are needed.
        AlgorithmParameters ap = null;
        byte[] encodedAlgParams = null;
        ap = cipher.getParameters();
        if (ap != null) {
            //get parameters to store away as example.
            encodedAlgParams = ap.getEncoded();
        }
        // use the unwrapped key for decryption
        cipher = Cipher.getInstance(cipherAlg, providerB);
        if (encodedAlgParams == null) {
            cipher.init(Cipher.DECRYPT_MODE, keyB);
        } else {
            //retrieve the algorithmParameters from the encoded array
            AlgorithmParameters aps =
                    AlgorithmParameters.getInstance(keyB.getAlgorithm());
            aps.init(encodedAlgParams);
            cipher.init(Cipher.DECRYPT_MODE, keyB, aps);
        }

        byte[] recovered = new byte[plaintext.length];
        int rLen = cipher.update(encryptedText, 0, encryptedText.length,
                recovered, 0);
        rLen += cipher.doFinal(recovered, rLen);

        if (!java.util.Arrays.equals(plaintext, recovered)) {
            throw new Exception("key do not match. unable to encrypt/decrypt.");
        }
    }

    /**
     *
     * @param symKey
     * @param wrapperAlg
     * @param wrapperKey
     * @param providerA
     * @param providerB
     * @throws Exception
     */
    public void wrapSymetricKey(Key symKey, String wrapperAlg,
            Key wrapperKey, String providerA,
            String providerB) throws Exception {
        try {


            System.out.print("Wrap " + symKey.getAlgorithm() + " " +
                    ((SecretKeyFacade) symKey).key.getStrength() +
                    " with " + wrapperKey.getAlgorithm() + " " +
                    ((SecretKeyFacade) wrapperKey).key.getStrength() +
                    " symmetric key. ");

            // wrap key
            Cipher cipher = Cipher.getInstance(wrapperAlg, providerA);
            cipher.init(Cipher.WRAP_MODE, wrapperKey);
            byte[] wrappedData = cipher.wrap(symKey);
            //generate the algorithm Parameters; they need to be
            //the same for encrypt/decrypt if they are needed.
            byte[] encodedKeyWrapAP = null;
            AlgorithmParameters ap = null;
            ap = cipher.getParameters();
            if (ap != null) {
                //get parameters to store away as example.
                encodedKeyWrapAP = ap.getEncoded();
            }


            // unwrap key
            cipher = Cipher.getInstance(wrapperAlg, providerA);
            if (encodedKeyWrapAP == null) {
                cipher.init(Cipher.UNWRAP_MODE, wrapperKey);
            } else {
                //retrieve the algorithmParameters from the encoded array
                AlgorithmParameters aps =
                        AlgorithmParameters.getInstance(
                        wrapperKey.getAlgorithm());
                aps.init(encodedKeyWrapAP);
                cipher.init(Cipher.UNWRAP_MODE, wrapperKey, aps);
            }

            SecretKey unwrappedKey = (SecretKey) cipher.unwrap(wrappedData,
                    symKey.getAlgorithm(), Cipher.SECRET_KEY);

            testKeys(symKey, unwrappedKey, providerA, providerB);

        } catch (BadPaddingException ex) {
            ex.printStackTrace();
            System.exit(1);
        } catch (IllegalBlockSizeException ex) {
            ex.printStackTrace();
            System.exit(1);
        } catch (UnsupportedEncodingException ex) {
            ex.printStackTrace();
            System.exit(1);
        } catch (InvalidKeyException ex) {
            ex.printStackTrace();
            System.exit(1);
        } catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace();
            System.exit(1);
        } catch (NoSuchPaddingException ex) {
            ex.printStackTrace();
            System.exit(1);
        }
    }
}
