/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss.crypto;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Hashtable;

import org.mozilla.jss.pkcs11.PKCS11Constants;
import org.mozilla.jss.pkcs11.KeyType;

public interface SymmetricKey extends javax.crypto.SecretKey {

    public static final Type GENERIC_SECRET = Type.GENERIC_SECRET;
    public static final Type DES = Type.DES;
    public static final Type DES3 = Type.DES3;
    public static final Type RC4 = Type.RC4;
    public static final Type RC2 = Type.RC2;
    public static final Type SHA1_HMAC = Type.SHA1_HMAC;
    public static final Type SHA256_HMAC = Type.SHA256_HMAC;
    public static final Type SHA384_HMAC = Type.SHA384_HMAC;
    public static final Type SHA512_HMAC = Type.SHA512_HMAC;
    public static final Type AES = Type.AES;

    public Type getType();

    public CryptoToken getOwningToken();

    public int getStrength();
    public int getLength();

    public byte[] getKeyData() throws NotExtractableException;

    public static class NotExtractableException extends Exception {
        private static final long serialVersionUID = 1L;
        public NotExtractableException() {
            super();
        }
        public NotExtractableException(String mesg) {
            super(mesg);
        }
    }

    String getAlgorithm();

    byte[] getEncoded();

    String getFormat();

    String getNickName();

    void setNickName(String nickName);

    public final static class Type {
        // all names converted to lowercase for case insensitivity
        private static Hashtable<String, Type> nameMap = new Hashtable<>();
        private static ArrayList<Type> allTypes = new ArrayList<>();

        private String[] names;
        private KeyGenAlgorithm keyGenAlg;
        private KeyType keyType;

        private Type() { }
        private Type(String[] names, KeyGenAlgorithm keyGenAlg, KeyType keyType) {
            this.names = names;
            this.keyGenAlg = keyGenAlg;
            this.keyType = keyType;

            for (String name : names) {
                nameMap.put(name.toLowerCase(), this);
            }

            allTypes.add(this);
        }

        public static final Type GENERIC_SECRET = new Type(new String[]{ "GenericSecret", "GENERIC_SECRET" }, KeyGenAlgorithm.GENERIC_SECRET, KeyType.GENERIC_SECRET);
        public static final Type DES = new Type(new String[]{ "DES" }, KeyGenAlgorithm.DES, KeyType.DES);
        public static final Type DES3 =
            new Type(new String[] { "DESede", "TDES", "3DES", "DES3" }, KeyGenAlgorithm.DES3, KeyType.DES3);
        public static final Type DESede = DES3;
        public static final Type RC4 = new Type(new String[]{ "RC4" }, KeyGenAlgorithm.RC4, KeyType.RC4);
        public static final Type RC2 = new Type(new String[]{ "RC2" }, KeyGenAlgorithm.RC2, KeyType.RC4);
        public static final Type SHA1_HMAC = new Type(new String[]{ "SHA1_HMAC", "SHA1-HMAC", "SHA1HMAC", "HMAC_SHA1", "HMAC-SHA1", "HMACSHA1" },
            KeyGenAlgorithm.SHA1_HMAC, KeyType.SHA1_HMAC);
        public static final Type SHA256_HMAC = new Type(new String[]{ "SHA256_HMAC", "SHA256-HMAC", "SHA256HMAC", "HMAC_SHA256", "HMAC-SHA256", "HMACSHA256" },
            KeyGenAlgorithm.SHA256_HMAC, KeyType.SHA256_HMAC);
        public static final Type SHA384_HMAC = new Type(new String[]{ "SHA384_HMAC", "SHA384-HMAC", "SHA384HMAC", "HMAC_SHA384", "HMAC-SHA384", "HMACSHA384" },
            KeyGenAlgorithm.SHA384_HMAC, KeyType.SHA384_HMAC);
        public static final Type SHA512_HMAC = new Type(new String[]{ "SHA512_HMAC", "SHA512-HMAC", "SHA512HMAC", "HMAC_SHA512", "HMAC-SHA512", "HMACSHA512" },
            KeyGenAlgorithm.SHA512_HMAC, KeyType.SHA512_HMAC);
        public static final Type PBA_SHA1_HMAC = new Type(new String[]{ "PBA_SHA1_HMAC" },
            KeyGenAlgorithm.PBA_SHA1_HMAC, null);
        public static final Type AES = new Type(new String[]{ "AES" }, KeyGenAlgorithm.AES, KeyType.AES);


        public String toString() {
            return names[0];
        }

        public String[] getAliases() {
            return names;
        }

        public KeyGenAlgorithm getKeyGenAlg() throws NoSuchAlgorithmException {
            if (keyGenAlg == null) {
                throw new NoSuchAlgorithmException(names[0]);
            }
            return keyGenAlg;
        }

        public KeyType getKeyType() {
            return keyType;
        }

        public static Type fromName(String name)
                throws NoSuchAlgorithmException
        {
            Object type = nameMap.get(name.toLowerCase());
            if (type == null) {
                throw new NoSuchAlgorithmException();
            } else {
                return (Type) type;
            }
        }

        public static Type fromKeyType(KeyType type)
        {
            for (Type current : allTypes) {
                if (current.getKeyType() == type) {
                    return current;
                }
            }
            return null;
        }
    }

    /**
     * In PKCS #11, each key can be marked with the operations it will
     * be used to perform. Some tokens require that a key be marked for
     * an operation before the key can be used to perform that operation;
     * other tokens don't care.
     *
     * <p>When you unwrap a symmetric key, you must specify which one of these
     * operations it will be used to perform.
     */
    public final static class Usage {
        private Usage() { }
        private Usage(int val, long pk11_val) {
            this.val = val;
            this.pk11_val = pk11_val;
        }

        private int val;
        private long pk11_val;

        public int getVal() { return val; }
        public long getPKCS11Constant() { return pk11_val; }

        // these enums must match the JSS_symkeyUsage list in Algorithm.c
        // and the opFlagForUsage list in PK11KeyGenerator.java
        public static final Usage ENCRYPT = new Usage(0, PKCS11Constants.CKA_ENCRYPT);
        public static final Usage DECRYPT = new Usage(1, PKCS11Constants.CKA_DECRYPT);
        public static final Usage WRAP = new Usage(2, PKCS11Constants.CKA_WRAP);
        public static final Usage UNWRAP = new Usage(3, PKCS11Constants.CKA_UNWRAP);
        public static final Usage SIGN = new Usage(4, PKCS11Constants.CKA_SIGN);
        public static final Usage VERIFY = new Usage(5, PKCS11Constants.CKA_VERIFY);
    }
}
