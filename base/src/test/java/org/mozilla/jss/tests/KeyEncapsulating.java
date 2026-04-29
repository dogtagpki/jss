//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//

package org.mozilla.jss.tests;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;
import javax.crypto.KEM;

import org.mozilla.jss.crypto.*;
import org.mozilla.jss.CryptoManager;

/**
 * KeyEncapsulating tests..
 *
 */

public class KeyEncapsulating {

    public static void main(String args[]) throws Exception {
        CryptoManager cm = CryptoManager.getInstance();
        CryptoToken token = cm.getInternalCryptoToken();
        CryptoToken keyToken = cm.getInternalKeyStorageToken();
        
        KeyPairGenerator kpg1 =
            keyToken.getKeyPairGenerator(KeyPairAlgorithm.MLKEM);
        kpg1.initialize(new NamedParameterSpec("ML-KEM-768"));
        kpg1.temporaryPairs(true);
        kpg1.sensitivePairs(true);
        KeyPair kp1 = kpg1.genKeyPair();
        java.security.PublicKey pub1 = kp1.getPublic();
        PrivateKey privk1 = (org.mozilla.jss.crypto.PrivateKey)kp1.getPrivate();

        
        checkEncapsulateDecapsulate("ML-KEM", pub1, privk1, 16);
        checkEncapsulateDecapsulate("ML-KEM", pub1, privk1, 32);
        
        KeyPairGenerator kpg2 =
            keyToken.getKeyPairGenerator(KeyPairAlgorithm.MLKEM);
        kpg2.initialize(new NamedParameterSpec("ML-KEM-1024"));
        kpg2.temporaryPairs(true);
        kpg2.sensitivePairs(true);
        KeyPair kp2 = kpg2.genKeyPair();
        kpg1.sensitivePairs(true);
        java.security.PublicKey pub2 = kp2.getPublic();
        PrivateKey privk2 = (org.mozilla.jss.crypto.PrivateKey)kp2.getPrivate();

        
        checkEncapsulateDecapsulate("ML-KEM", pub2, privk2, 16);
        checkEncapsulateDecapsulate("ML-KEM", pub2, privk2, 32);

        //Verify the key has to match the encapsulating algorithm
        try {
            checkEncapsulateDecapsulate("ML-KEM-512", pub2, privk2, 16);
            throw new Exception("Invalid key not detected");
        } catch (InvalidKeyException ike) {
        }
        System.out.println("KeyEncapsulating test passed");
    }

    private static void
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

    private static void checkEncapsulateDecapsulate(String encAlg, PublicKey pub, PrivateKey privk, int aesSize) throws Exception {

        CryptoManager cm = CryptoManager.getInstance();
        CryptoToken token = cm.getInternalCryptoToken();
        
        EncryptionAlgorithm aes = switch(aesSize) {
            case 16 -> EncryptionAlgorithm.AES_128_ECB;
            case 24 -> EncryptionAlgorithm.AES_192_ECB;
            case 32 -> EncryptionAlgorithm.AES_256_ECB;
            default -> throw new InvalidAlgorithmParameterException();
        };
        
        KEM ks = KEM.getInstance(encAlg, "Mozilla-JSS");
        KEM.Encapsulator enc = ks.newEncapsulator(pub);
        KEM.Encapsulated encap = enc.encapsulate(0, aesSize, "AES-ECB");


        byte[] msg = encap.encapsulation();
        SymmetricKey sksE = (SymmetricKey) encap.key();

        byte[] plaintext = new byte[] {
            (byte)0x73, (byte)0x24, (byte)0x51, (byte)0x48,
            (byte)0x32, (byte)0x87, (byte)0x23, (byte)0x33,
            (byte)0x65, (byte)0x5f, (byte)0x73, (byte)0x9e,
            (byte)0x8b, (byte)0xb6, (byte)0x69, (byte)0x90
        };
        byte[] plaintextPad = Cipher.pad(plaintext,
                                    aes.getBlockSize());

        System.out.println("plaintext length is " + plaintextPad.length);

        Cipher encryptor = token.getCipherContext(aes);
        encryptor.initEncrypt(sksE);
        byte[] ciphertext = encryptor.doFinal(plaintextPad);
        System.out.println("ciphertext length is " + ciphertext.length);

        KEM.Decapsulator dec = ks.newDecapsulator(privk);
        SymmetricKey sksD = (SymmetricKey) dec.decapsulate(msg, 0, aesSize, "AES-ECB");

        Cipher decryptor = token.getCipherContext(aes);
        decryptor.initDecrypt(sksD);
        byte[] recoveredPad = decryptor.doFinal(ciphertext);
        System.out.println("Decrypted "+ recoveredPad.length+ " bytes");
        byte[] recovered = Cipher.unPad(recoveredPad,
                            aes.getBlockSize());

        System.out.println("plaintext:");
        displayByteArray(plaintext);
        System.out.println("ciphertext:");
        displayByteArray(ciphertext);
        System.out.println("recovered:");
        displayByteArray(recovered);
        
        assert Arrays.equals(plaintext, recovered);
    }
}
