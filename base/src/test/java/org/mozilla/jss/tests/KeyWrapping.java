/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.tests;

import java.security.KeyPair;
import java.security.spec.MGF1ParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.OAEPParameterSpec;

import org.mozilla.jss.crypto.*;
import org.mozilla.jss.CryptoManager;

/**
 * Keywrapping tests..
 *
 */

public class KeyWrapping {

    public static void main(String args[]) throws Exception {
        CryptoManager cm = CryptoManager.getInstance();
        CryptoToken token = cm.getInternalCryptoToken();
        CryptoToken keyToken = cm.getInternalKeyStorageToken();
        KeyGenerator kg = token.getKeyGenerator(KeyGenAlgorithm.AES);
        KeyGenerator keyKg = keyToken.getKeyGenerator(KeyGenAlgorithm.AES);
        kg.initialize(256);
        keyKg.initialize(256);

        SymmetricKey wrapped = kg.generate();
        SymmetricKey wrapper = kg.generate();
        SymmetricKey keyWrapper = keyKg.generate();
        SymmetricKey keyWrapped = keyKg.clone(wrapped);

        // wrap a symmetric with a symmetric
        byte[] plaintextPre = new byte[] {
            (byte)0x73, (byte)0x24, (byte)0x51, (byte)0x48,
            (byte)0x32, (byte)0x87, (byte)0x23, (byte)0x33,
            (byte)0x65, (byte)0x5f, (byte)0x73, (byte)0x9e,
            (byte)0x8b, (byte)0xb6, (byte)0x69, (byte)0x90
        };
        byte[] plaintext = Cipher.pad(plaintextPre,
                                    EncryptionAlgorithm.AES_256_ECB.getBlockSize());

        System.out.println("plaintext length is " + plaintext.length);

        Cipher encryptor = token.getCipherContext(EncryptionAlgorithm.AES_256_ECB);
        encryptor.initEncrypt(wrapped);
        byte[] ciphertext = encryptor.doFinal(plaintext);

        System.out.println("ciphertext length is " + ciphertext.length);

        KeyWrapper keyWrap = token.getKeyWrapper(KeyWrapAlgorithm.AES_ECB);
        keyWrap.initWrap(wrapper,null);
        byte[] wrappedKey = keyWrap.wrap(wrapped);

        keyWrap.initUnwrap(wrapper, null);
        SymmetricKey unwrapped = keyWrap.unwrapSymmetric(wrappedKey,
            SymmetricKey.AES, SymmetricKey.Usage.DECRYPT, 0);

        Cipher decryptor = token.getCipherContext(EncryptionAlgorithm.AES_256_ECB);
        decryptor.initDecrypt(unwrapped);
        byte[] recoveredPre = decryptor.doFinal(ciphertext);
        System.out.println("Decrypted "+ recoveredPre.length+ " bytes");
        byte[] recovered = Cipher.unPad(recoveredPre,
                            EncryptionAlgorithm.AES_256_ECB.getBlockSize());

        System.out.println("plaintext:");
        displayByteArray(plaintextPre);
        System.out.println("ciphertext:");
        displayByteArray(ciphertext);
        System.out.println("recovered:");
        displayByteArray(recovered);

        // wrap a private with a symmetric
        keyWrap = keyToken.getKeyWrapper(KeyWrapAlgorithm.AES_CBC_PAD);
        IVParameterSpec iv = new IVParameterSpec(recovered);
        keyWrap.initWrap(keyWrapper, iv);
        KeyPairGenerator kpg =
            keyToken.getKeyPairGenerator(KeyPairAlgorithm.RSA);
        kpg.initialize(Policy.RSA_MINIMUM_KEY_SIZE);
        kpg.temporaryPairs(true);
        KeyPair kp = kpg.genKeyPair();
        java.security.PublicKey pub = kp.getPublic();
        PrivateKey privk = (org.mozilla.jss.crypto.PrivateKey)kp.getPrivate();

        wrappedKey = keyWrap.wrap(privk);
        System.out.println("Original key:");
        displayByteArray(privk.getUniqueID());
        privk = null; kp = null;

        keyWrap.initUnwrap(keyWrapper, iv);
        PrivateKey newPrivk = keyWrap.unwrapTemporaryPrivate(wrappedKey,
            PrivateKey.RSA, pub );

        // wrap a private with a symmetric using AES_KEY_WRAP_PAD
        keyWrap = keyToken.getKeyWrapper(KeyWrapAlgorithm.AES_KEY_WRAP_PAD);
        // IVParameterSpec iv = new IVParameterSpec(recovered);
        keyWrap.initWrap(keyWrapper, null /*iv*/);
        KeyPairGenerator kpg2 =
            keyToken.getKeyPairGenerator(KeyPairAlgorithm.RSA);
        kpg2.initialize(Policy.RSA_MINIMUM_KEY_SIZE);
        kpg2.temporaryPairs(true);
        KeyPair kp2 = kpg2.genKeyPair();
        java.security.PublicKey pub2 = kp2.getPublic();
        PrivateKey privk2 = (org.mozilla.jss.crypto.PrivateKey)kp2.getPrivate();

        wrappedKey = keyWrap.wrap(privk2);
        System.out.println("Original key:");
        displayByteArray(privk2.getUniqueID());
        privk2 = null; kp2 = null;
        //keyToken.getCryptoStore().deletePrivateKey(privk);

        keyWrap.initUnwrap(keyWrapper, null /*iv*/);
        PrivateKey newPrivk2 = keyWrap.unwrapTemporaryPrivate(wrappedKey,
            PrivateKey.RSA, pub );

        System.out.println("New key:");
        displayByteArray(newPrivk2.getUniqueID());

        System.out.println("New key:");
        displayByteArray(newPrivk2.getUniqueID());

        // wrap a symmetric with a private
        keyWrap = keyToken.getKeyWrapper(KeyWrapAlgorithm.RSA);
        keyWrap.initWrap(pub,null);
        wrappedKey = keyWrap.wrap(keyWrapped);
        System.out.println("Wrapped key:");
        displayByteArray(wrappedKey);
        keyWrap.initUnwrap(newPrivk, null);
        unwrapped = keyWrap.unwrapSymmetric(wrappedKey, SymmetricKey.AES,
            SymmetricKey.Usage.DECRYPT, 0);
        unwrapped = kg.clone(unwrapped);
        decryptor = token.getCipherContext(EncryptionAlgorithm.AES_256_ECB);
        decryptor.initDecrypt(unwrapped);
        recovered = decryptor.doFinal(ciphertext);
        System.out.println("Recovered again:");
        displayByteArray(Cipher.unPad(recovered, EncryptionAlgorithm.AES_256_ECB.getBlockSize()));

        // try a RSA-OAEP operation
        keyWrap = keyToken.getKeyWrapper(KeyWrapAlgorithm.RSA_OAEP);
        OAEPParameterSpec config = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
        keyWrap.initWrap(pub, config);
        wrappedKey = keyWrap.wrap(keyWrapped);
        System.out.println("Wrapped key:");
        displayByteArray(wrappedKey);
        keyWrap.initUnwrap(newPrivk, config);
        unwrapped = keyWrap.unwrapSymmetric(wrappedKey, SymmetricKey.AES,
            SymmetricKey.Usage.DECRYPT, 0);
        unwrapped = kg.clone(unwrapped);
        decryptor = token.getCipherContext(EncryptionAlgorithm.AES_256_ECB);
        decryptor.initDecrypt(unwrapped);
        recovered = decryptor.doFinal(ciphertext);
        System.out.println("Recovered again:");
        displayByteArray(Cipher.unPad(recovered, EncryptionAlgorithm.AES_256_ECB.getBlockSize()));
    }

    public static void
    displayByteArray(byte[] ba) {
        System.out.print("[" + ba.length + " bytes] ");
        for(int i=0; i < ba.length; i++) {
            System.out.print( Integer.toHexString(ba[i]&0xff) + " " );
            if( (i % 26) == 25 ) {
                System.out.println("");
            }
        }
        System.out.println("");
    }
}
