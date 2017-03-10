/* ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is the Netscape Security Services for Java.
 *
 * The Initial Developer of the Original Code is
 * Netscape Communications Corporation.
 * Portions created by the Initial Developer are Copyright (C) 1998-2000
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either the GNU General Public License Version 2 or later (the "GPL"), or
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the MPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the MPL, the GPL or the LGPL.
 *
 * ***** END LICENSE BLOCK ***** */

package org.mozilla.jss.tests;

import org.mozilla.jss.crypto.*;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.util.Assert;
import org.mozilla.jss.pkcs11.*;
import sun.security.pkcs11.wrapper.PKCS11Constants;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Vector;
import java.util.Enumeration;

/**
 * Sym Key deriving tests..
 *
 */

public class SymKeyDeriving {

      private static final byte[] iv8 = new byte [] { 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8 };
      private static final byte[] iv16 = new byte [] { 0x1, 0x2, 0x3, 0x4, 
                    0x5, 0x6, 0x7, 0x8,  
                    0x9,0xa, 0xb, 0xc,0xd,0xe, 0xf,0x10 };

      private static final byte[] derivationData1 = new byte[] { 0x11, 0x11, 0x13,
          0x14, 0x15, 0x16, 0x17, 0x18 };

      private static final byte[] derivationData2 = new byte [] { 0x9, 0xa, 0xb, 0xc, 0xd,
          0xe, 0xf, 0x10 };

      private static final byte[] derivationData16 = new byte[] { 0x1, 0x2, 0x3, 0x4, 0x5, 0x6,0x7, 0x8,
          0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10 };


    public static void main(String args[]) {

      SymmetricKey macKeyDev = null;
      try {

        CryptoManager.InitializationValues vals =
              new CryptoManager.InitializationValues("./"
              );
        CryptoManager.initialize(vals);
        CryptoManager cm = CryptoManager.getInstance();
        CryptoToken token = cm.getInternalCryptoToken();
        CryptoToken keyToken = cm.getInternalKeyStorageToken();
        System.out.println("interal token name: " + keyToken.getName());
        KeyGenerator keyKg = keyToken.getKeyGenerator(KeyGenAlgorithm.DES3);
        SymmetricKey baseKey = keyKg.generate();


        KeyGenerator keyKgDes = keyToken.getKeyGenerator(KeyGenAlgorithm.DES);
        SymmetricKey baseKeyDes = keyKgDes.generate();
        System.out.println("strength: " + baseKeyDes.getStrength());


        KeyGenerator keyKgAES = keyToken.getKeyGenerator(KeyGenAlgorithm.AES);
        keyKgAES.initialize(128);
        SymmetricKey baseKeyAES = keyKgAES.generate();



        System.out.println("baseKey bytes: ");
        byte[] baseBytes = baseKey.getEncoded();
        displayByteArray(baseBytes,true); 


        /*****************************************************************************************************/

        System.out.println("\n Mechanism CKM_EXTRACT_KEY_FROM_KEY test 16 bytes. \n");


        SymmetricKeyDeriver deriver = token.getSymmetricKeyDeriver();
        System.out.println("deriver: " + deriver);
        System.out.println("CKM_EXTRACT_KEY_FROM_KEY : " + PKCS11Constants.CKM_EXTRACT_KEY_FROM_KEY);

        long bitPosition = 0;

        byte[] param = longToBytes(bitPosition);

        deriver.initDerive(
                           baseKey, PKCS11Constants.CKM_EXTRACT_KEY_FROM_KEY,param,null, 
                           PKCS11Constants.CKA_ENCRYPT, PKCS11Constants.CKA_DERIVE,(long) 16);


        SymmetricKey extracted16 = deriver.derive();

        System.out.println("Derived key: " + extracted16);

        if(extracted16 == null) {
            System.out.println("Failed to derive 16 byte key with mechanism: CKM_EXTRACT_KEY_FROM_KEY \n");
        }

        System.out.println("derivedKey 16 bytes: ");
        byte[] derivedBytes = extracted16.getEncoded();
        displayByteArray(derivedBytes,true);


        /*****************************************************************************************************/

        System.out.println("\n Mechanism CKM_EXTRACT_KEY_FROM_KEY test 8 bytes. \n");


        SymmetricKeyDeriver extract8 = token.getSymmetricKeyDeriver();
        extract8.initDerive(
                           extracted16, PKCS11Constants.CKM_EXTRACT_KEY_FROM_KEY,param,null,
                           PKCS11Constants.CKA_ENCRYPT, PKCS11Constants.CKA_DERIVE,(long) 8);


       SymmetricKey extracted8 = extract8.derive();
       System.out.println("Derived key: " + extracted8);

        if(extracted8 == null) {
            System.out.println("Failed to derive key extracted 8 bytes with mechanism: CKM_EXTRACT_KEY_FROM_KEY \n");
        }

        byte[] extracted8Bytes = extracted8.getEncoded();
        System.out.println("derived extracted 8 bytes of key: ");
        displayByteArray(extracted8Bytes,true);


        /*****************************************************************************************************/


         System.out.println("\n Mechanism CKM_CONCATENATE_BASE_AND_KEY test 16 + 8 = 24 byte key. \n");

        SymmetricKeyDeriver concat = keyToken.getSymmetricKeyDeriver();
        concat.initDerive(
                           extracted16,extracted8, PKCS11Constants.CKM_CONCATENATE_BASE_AND_KEY,null,null,
                           PKCS11Constants.CKM_DES3_ECB, PKCS11Constants.CKA_DERIVE,(long) 0);

        SymmetricKey concated24 =  concat.derive();

        if( concated24 == null) {
            System.out.println("Failed to derive key concated 8 bytes to 16 bytes key: CKM_CONCATENATE_BASE_AND_KEY \n");
        }

        byte[] concated24Bytes = concated24.getEncoded();
        System.out.println("derived concated 16 + 8 = 24 byte key: ");
        displayByteArray(concated24Bytes,true);

        /*****************************************************************************************************/

        // Now lets try  more complex derivation

       // tmp2 = PK11_Derive( master , CKM_DES_ECB_ENCRYPT_DATA , &param , CKM_CONCATENATE_BASE_AND_KEY , CKA_DERIVE , 0);

       System.out.println("\n Mechanism CKM_DES_ECB_ENCRYPT_DATA test. \n");

       SymmetricKeyDeriver encrypt = token.getSymmetricKeyDeriver();

       encrypt.initDerive(
                           baseKeyDes, /* PKCS11Constants.CKM_DES_ECB_ENCRYPT_DATA */ 4352L,derivationData1 ,null,
                           PKCS11Constants.CKM_DES_ECB, PKCS11Constants.CKA_DERIVE,(long) 8);

       SymmetricKey encrypted8 = encrypt.derive();

       if( encrypted8 == null) {
            System.out.println("Failed to derive  8 bytes from encrypted derivation data.");
        }

        byte[] encrypted8Bytes = encrypted8.getEncoded();
        System.out.println("derived encrypted 8 bytes: " + encrypted8Bytes.length);
        displayByteArray(encrypted8Bytes,true);

        Cipher cipher = null;
        cipher =  keyToken.getCipherContext(EncryptionAlgorithm.DES_ECB);

        cipher.initEncrypt(baseKeyDes);

        byte[] ciphertext = cipher.doFinal(derivationData1);
        displayByteArray(ciphertext,true);

        if ( ciphertext.length != encrypted8Bytes.length ) {
            System.out.println("FAILED: encrypted data length not equal to derived key length.");
        } else {
            for ( int i = 0; i < ciphertext.length ; i ++) {
                ciphertext[i]&=0xfe;
                encrypted8Bytes[i]&=0xfe;
            }
            if ( Arrays.equals(ciphertext, encrypted8Bytes)) {
                System.out.println("PASSED: derived key the same as encrypted data.");
            } else {

                System.out.println("FAILED: derived key not the same as encrypted data.");
            }
        }


        /*****************************************************************************************************/

        // Try ecnrypted des3 derivation

       System.out.println("\n Mechanism CKM_DES3_ECB_ENCRYPT_DATA test. \n");

       SymmetricKeyDeriver encryptDes3 = token.getSymmetricKeyDeriver();

       encryptDes3.initDerive(
                           baseKey, /* PKCS11Constants.CKM_DES3_ECB_ENCRYPT_DATA */ 4354L  ,derivationData16 ,null,
                           PKCS11Constants.CKM_DES3_ECB, PKCS11Constants.CKA_DERIVE,(long) 16);


       SymmetricKey encrypted16 = encryptDes3.derive();

       if ( encrypted16 == null) {
           System.out.println("Failed to derive 16 bytes from encrypted derivation data.");
       }

       byte[] encrypted16Bytes = encrypted16.getEncoded();

       System.out.println("derived encrypted 16 bytes: " + encrypted16Bytes.length);
       displayByteArray(encrypted16Bytes,true);


       cipher =  keyToken.getCipherContext(EncryptionAlgorithm.DES3_ECB);
       cipher.initEncrypt(baseKey);
       ciphertext = cipher.doFinal(derivationData16);
       displayByteArray(ciphertext,true);

       if ( ciphertext.length != encrypted16Bytes.length ) {
           System.out.println("FAILED: encrypted data length not equal to derived key length.");
       } else {
           for ( int i = 0; i < ciphertext.length ; i ++) {
               ciphertext[i]&=0xfe;
               encrypted16Bytes[i]&=0xfe;
           }
           if ( Arrays.equals(ciphertext, encrypted16Bytes)) {
               System.out.println("PASSED: derived key the same as encrypted data.");
           } else {
               System.out.println("FAILED: derived key not the same as encrypted data.");
           }
       }


       /*****************************************************************************************************/

       System.out.println("\n Mechanism CKM_DES_CBC_ENCRYPT_DATA test. \n");

       SymmetricKeyDeriver encryptDesCBC = token.getSymmetricKeyDeriver();

       encryptDesCBC.initDerive(
                           baseKeyDes, /* PKCS11Constants.CKM_DES_CBC_ENCRYPT_DATA */ 4353L  ,derivationData1 ,iv8,
                           PKCS11Constants.CKM_DES_CBC, PKCS11Constants.CKA_DERIVE,(long) 8);


       SymmetricKey encryptedDesCBC = encryptDesCBC.derive();

       if ( encryptedDesCBC == null) {
           System.out.println("Failed to derive 8 bytes from encrypted derivation data.");
       }

       byte[] encryptedDesCBCBytes = encryptedDesCBC.getEncoded();

       System.out.println("derived encrypted 8 bytes: " + encryptedDesCBCBytes.length);
       displayByteArray(encryptedDesCBCBytes,true);


       cipher =  keyToken.getCipherContext(EncryptionAlgorithm.DES_CBC);
       cipher.initEncrypt(baseKeyDes,new IVParameterSpec(iv8));
       ciphertext = cipher.doFinal(derivationData1);
       displayByteArray(ciphertext,true);

        if ( ciphertext.length != encryptedDesCBCBytes.length ) {
            System.out.println("FAILED: encrypted data length not equal to derived key length.");
        } else {
            for ( int i = 0; i < ciphertext.length ; i ++) {
                ciphertext[i]&=0xfe;
                encryptedDesCBCBytes[i]&=0xfe;
            }
            if ( Arrays.equals(ciphertext, encryptedDesCBCBytes)) {
                System.out.println("PASSED: derived key the same as encrypted data.");
            } else {

                System.out.println("FAILED: derived key not the same as encrypted data.");
            }
        }

        /*****************************************************************************************************/

       System.out.println("\n Mechanism CKM_DES3_CBC_ENCRYPT_DATA test. \n");
        
       SymmetricKeyDeriver encryptDes3CBC = token.getSymmetricKeyDeriver();

       encryptDes3CBC.initDerive(
                           baseKey, /* PKCS11Constants.CKM_DES3_CBC_ENCRYPT_DATA */ 4355L  ,derivationData16 ,iv8,
                           PKCS11Constants.CKM_DES3_CBC, PKCS11Constants.CKA_DERIVE,(long) 16);
        

       SymmetricKey encryptedDes3CBC = encryptDes3CBC.derive();
        
       if ( encryptedDes3CBC == null) {
           System.out.println("Failed to derive 16 bytes from encrypted derivation data.");
       }
        
       byte[] encryptedDes3CBCBytes = encryptedDes3CBC.getEncoded();

       System.out.println("derived encrypted 16 bytes: " + encryptedDes3CBCBytes.length);
       displayByteArray(encryptedDes3CBCBytes,true);


       cipher =  keyToken.getCipherContext(EncryptionAlgorithm.DES3_CBC);
       cipher.initEncrypt(baseKey,new IVParameterSpec(iv8));
       ciphertext = cipher.doFinal(derivationData16);
       displayByteArray(ciphertext,true);

        if ( ciphertext.length != encryptedDes3CBCBytes.length ) {
            System.out.println("FAILED: encrypted data length not equal to derived key length.");
        } else {
            for ( int i = 0; i < ciphertext.length ; i ++) {
                ciphertext[i]&=0xfe;
                encryptedDes3CBCBytes[i]&=0xfe;
            }
            if ( Arrays.equals(ciphertext, encryptedDes3CBCBytes)) {
                System.out.println("PASSED: derived key the same as encrypted data.");
            } else {

                System.out.println("FAILED: derived key not the same as encrypted data.");
            }
        }

        /*****************************************************************************************************/

       System.out.println("\n Mechanism CKM_AES_ECB_ENCRYPT_DATA test. \n");

       SymmetricKeyDeriver encryptAESECB = token.getSymmetricKeyDeriver();

       //System.in.read();
       encryptAESECB.initDerive(
                           baseKeyAES, /* PKCS11Constants.CKM_AES_ECB_ENCRYPT_DATA */ 4356L  ,derivationData16 ,null,
                           PKCS11Constants.CKM_AES_ECB, PKCS11Constants.CKA_DERIVE,(long) 16);


       SymmetricKey encryptedAESECB = encryptAESECB.derive();

       if ( encryptedAESECB == null) {
           System.out.println("Failed to derive 16 bytes from encrypted derivation data.");
       }

       byte[] encryptedAESECBBytes = encryptedAESECB.getEncoded();

       System.out.println("derived encrypted 16 bytes: " + encryptedAESECBBytes.length);
       displayByteArray(encryptedAESECBBytes,true);


       cipher =  keyToken.getCipherContext(EncryptionAlgorithm.AES_128_ECB);
       cipher.initEncrypt(baseKeyAES);
       ciphertext = cipher.doFinal(derivationData16);
       displayByteArray(ciphertext,true);

        if ( ciphertext.length != encryptedAESECBBytes.length ) {
            System.out.println("FAILED: encrypted data length not equal to derived key length.");
        } else {
            for ( int i = 0; i < ciphertext.length ; i ++) {
                ciphertext[i]&=0xfe;
                encryptedAESECBBytes[i]&=0xfe;
            }
            if ( Arrays.equals(ciphertext, encryptedAESECBBytes)) {
                System.out.println("PASSED: derived key the same as encrypted data.");
            } else {

                System.out.println("FAILED: derived key not the same as encrypted data.");
            }
        }


       /*****************************************************************************************************/

       System.out.println("\n Mechanism CKM_AES_CBC_ENCRYPT_DATA test. \n");

       SymmetricKeyDeriver encryptAESCBC= token.getSymmetricKeyDeriver();

       //System.in.read();
       encryptAESCBC.initDerive(
                           baseKeyAES, /* PKCS11Constants.CKM_AES_CBC_ENCRYPT_DATA */ 4357L  ,derivationData16 ,iv16,
                           PKCS11Constants.CKM_AES_CBC, PKCS11Constants.CKA_DERIVE,(long) 16);


       SymmetricKey encryptedAESCBC = encryptAESCBC.derive();

       if ( encryptedAESCBC == null) {
           System.out.println("Failed to derive 16 bytes from encrypted derivation data.");
       }

       byte[] encryptedAESCBCBytes = encryptedAESCBC.getEncoded();

       System.out.println("derived encrypted 16 bytes: " + encryptedAESCBCBytes.length);
       displayByteArray(encryptedAESCBCBytes,true);


       cipher =  keyToken.getCipherContext(EncryptionAlgorithm.AES_128_CBC);
       cipher.initEncrypt(baseKeyAES,new IVParameterSpec(iv16));
       ciphertext = cipher.doFinal(derivationData16);
       displayByteArray(ciphertext,true);

        if ( ciphertext.length != encryptedAESCBCBytes.length ) {
            System.out.println("FAILED: encrypted data length not equal to derived key length.");
        } else {
            for ( int i = 0; i < ciphertext.length ; i ++) {
                ciphertext[i]&=0xfe;
                encryptedAESCBCBytes[i]&=0xfe;
            }
            if ( Arrays.equals(ciphertext, encryptedAESCBCBytes)) {
                System.out.println("PASSED: derived key the same as encrypted data.");
            } else {

                System.out.println("FAILED: derived key not the same as encrypted data.");
            }
        }

        // get vector of symkeys

        Enumeration<CryptoToken> ect = null; 
        ect = (Enumeration<CryptoToken>) cm.getAllTokens(); 
        CryptoToken ct = null; //ct = cm.getTokenByName("ePass Token"); 
        while (ect.hasMoreElements()) 
        { 
          ct = ect.nextElement(); 
          System.out.println("CryptoToken.name= " + ct.getName()); 
        } 

        SymmetricKey[] keys = keyToken.getCryptoStore().getSymmetricKeys();

        SymmetricKey macKey = getSymKeyByName(keys, "defKeySet-macKey");

        System.out.println("macKey: " + macKey);

      } catch(Exception e) {
        e.printStackTrace();
      }
    }

    public static void
    displayByteArray(byte[] ba, boolean has_check_sum) {
        char mask = 0xff;

        if ( has_check_sum == true )
            mask = 0xfe;

        for(int i=0; i < ba.length; i++) {
 
            System.out.print( Integer.toHexString(ba[i]&mask) + " " );
            if( (i % 26) == 25 ) {
                System.out.println("");
            }
        }
        System.out.println("");
    }

    public static  byte[] longToBytes(long x) {
        ByteBuffer buffer = ByteBuffer.allocate(8);
        buffer.putLong(x);
        return buffer.array();
    }

    public static byte[] concatByteArrays(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length]; 
        System.arraycopy(a, 0, result, 0, a.length); 
        System.arraycopy(b, 0, result, a.length, b.length); 
        return result;
    }

    public static SymmetricKey getSymKeyByName( SymmetricKey[] keys, String name) {
        if ( keys == null || name == null ) {
            return null;
        }

        int len = keys.length;
        for(int i = 0 ; i < len ; i++ ) {
            SymmetricKey cur = keys[i];
            if ( cur != null ) {
                if( name.equals(cur.getNickName())) {
                    System.out.println("Found key: " + name + "\n");
                    return cur; 
                }
            }
        }

        return null;
    }
}
