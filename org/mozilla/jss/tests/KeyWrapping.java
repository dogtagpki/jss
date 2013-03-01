/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.tests;

import org.mozilla.jss.crypto.*;
import org.mozilla.jss.CryptoManager;
import java.security.KeyPair;

/**
 * Keywrapping tests..
 *
 */

public class KeyWrapping {

    public static void main(String args[]) {

      try {

        CryptoManager.initialize(".");
        CryptoManager cm = CryptoManager.getInstance();
        CryptoToken token = cm.getInternalCryptoToken();
        CryptoToken keyToken = cm.getInternalKeyStorageToken();
        KeyGenerator kg = token.getKeyGenerator(KeyGenAlgorithm.DES);
        KeyGenerator keyKg = keyToken.getKeyGenerator(KeyGenAlgorithm.DES3);

        SymmetricKey wrapped = kg.generate();
        SymmetricKey wrapper = kg.generate();
        SymmetricKey keyWrapper = keyKg.generate();
        SymmetricKey keyWrapped = keyKg.clone(wrapped);

        // wrap a symmetric with a symmetric
        byte[] plaintextPre = new byte[] {
            (byte)0x73, (byte)0x24, (byte)0x51, (byte)0x48,
            (byte)0x32, (byte)0x87, (byte)0x23, (byte)0x33, (byte)0x65};
        byte[] plaintext = Cipher.pad(plaintextPre,
                                    EncryptionAlgorithm.DES_ECB.getBlockSize());

        System.out.println("plaintext length is " + plaintext.length);

        Cipher encryptor = token.getCipherContext(EncryptionAlgorithm.DES_ECB);
        encryptor.initEncrypt(wrapped);
        byte[] ciphertext = encryptor.doFinal(plaintext);

        System.out.println("ciphertext length is " + ciphertext.length);

        KeyWrapper keyWrap = token.getKeyWrapper(KeyWrapAlgorithm.DES_ECB);
        keyWrap.initWrap(wrapper,null);
        byte[] wrappedKey = keyWrap.wrap(wrapped);

        keyWrap.initUnwrap(wrapper, null);
        SymmetricKey unwrapped = keyWrap.unwrapSymmetric(wrappedKey,
            SymmetricKey.DES, SymmetricKey.Usage.DECRYPT, 0);

        Cipher decryptor = token.getCipherContext(EncryptionAlgorithm.DES_ECB);
        decryptor.initDecrypt(unwrapped);
        byte[] recoveredPre = decryptor.doFinal(ciphertext);
        System.out.println("Decrypted "+ recoveredPre.length+ " bytes");
        byte[] recovered = Cipher.unPad(recoveredPre,
                            EncryptionAlgorithm.DES_ECB.getBlockSize());

        System.out.println("plaintext:");
        displayByteArray(plaintextPre);
        System.out.println("ciphertext:");
        displayByteArray(ciphertext);
        System.out.println("recovered:");
        displayByteArray(recovered);
        

        // wrap a private with a symmetric
        keyWrap = keyToken.getKeyWrapper(KeyWrapAlgorithm.DES3_CBC_PAD);
        IVParameterSpec iv = new IVParameterSpec(recovered);
        keyWrap.initWrap(keyWrapper,iv);
        KeyPairGenerator kpg =
            keyToken.getKeyPairGenerator(KeyPairAlgorithm.RSA);
        kpg.initialize(512);
        kpg.temporaryPairs(true);
        KeyPair kp = kpg.genKeyPair();
        java.security.PublicKey pub = kp.getPublic();
        PrivateKey privk = (org.mozilla.jss.crypto.PrivateKey)kp.getPrivate();

        wrappedKey = keyWrap.wrap(privk);
        System.out.println("Original key:");
        displayByteArray(privk.getUniqueID());
        privk = null; kp = null;
        //keyToken.getCryptoStore().deletePrivateKey(privk);

        keyWrap.initUnwrap(keyWrapper,iv);
        PrivateKey newPrivk = keyWrap.unwrapTemporaryPrivate(wrappedKey,
            PrivateKey.RSA, pub );

        System.out.println("New key:");
        displayByteArray(newPrivk.getUniqueID());

        // wrap a symmetric with a private
        keyWrap = keyToken.getKeyWrapper(KeyWrapAlgorithm.RSA);
        keyWrap.initWrap(pub,null);
        wrappedKey = keyWrap.wrap(keyWrapped);
        keyWrap.initUnwrap(newPrivk, null);
        unwrapped = keyWrap.unwrapSymmetric(wrappedKey, SymmetricKey.DES,
            SymmetricKey.Usage.DECRYPT, 0);
        unwrapped = kg.clone(unwrapped);
        decryptor = token.getCipherContext(EncryptionAlgorithm.DES_ECB);
        decryptor.initDecrypt(unwrapped);
        recovered = decryptor.doFinal(ciphertext);
        System.out.println("Recovered again:");
        displayByteArray(Cipher.unPad(recovered, 8));
        

      } catch(Exception e) {
        e.printStackTrace();
      }
    }

    public static void
    displayByteArray(byte[] ba) {
        for(int i=0; i < ba.length; i++) {
            System.out.print( Integer.toHexString(ba[i]&0xff) + " " );
            if( (i % 26) == 25 ) {
                System.out.println("");
            }
        }
        System.out.println("");
    }
}
