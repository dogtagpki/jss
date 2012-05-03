/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.crypto;

import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;
import java.util.Hashtable;
import org.mozilla.jss.util.Assert;
import java.security.NoSuchAlgorithmException;

/**
 * Private Keys used by JSS.  All the private keys handled by JSS are
 * of this type, which is a subtype of java.security.PrivateKey.
 */
public interface PrivateKey extends java.security.PrivateKey
{

    public static final Type RSA = Type.RSA;
    public static final Type DSA = Type.DSA;
    public static final Type EC = Type.EC;
    public static final Type DiffieHellman = Type.DiffieHellman;

    /**
     * Returns the type (RSA or DSA) of this private key.
     */
    public Type getType();

    /**
     * Returns the unique ID of this key.  Unique IDs can be used to match
     * certificates to keys.
     *
     * @see org.mozilla.jss.crypto.TokenCertificate#getUniqueID
     * @deprecated This ID is based on an implementation that might change.
     *      If this functionality is required, it should be provided in
     *      another way, such as a function that directly matches a cert and
     *      key.
     */
    public byte[] getUniqueID() throws TokenException;

    /**
     * Returns the size, in bits, of the modulus of an RSA key.
     * Returns -1 for other types of keys.
     */
    public int getStrength();

    /**
     * Returns the CryptoToken that owns this private key. Cryptographic
     * operations with this key may only be performed on the token that
     * owns the key.
     */
    public CryptoToken getOwningToken();

    public static final class Type {
        private OBJECT_IDENTIFIER oid;
        private String name;
        private int pkcs11Type;

        private Type() { }

        private Type(OBJECT_IDENTIFIER oid, String name, int pkcs11Type) {
            this.oid = oid;
            this.name = name;
            Object old = oidMap.put(oid, this);
            this.pkcs11Type = pkcs11Type;
            Assert._assert( old == null );
        }

        private static Hashtable oidMap = new Hashtable();


        public static Type fromOID(OBJECT_IDENTIFIER oid)
            throws NoSuchAlgorithmException
        {
            Object obj = oidMap.get(oid);
            if( obj == null ) {
                throw new NoSuchAlgorithmException();
            }
            return (Type) obj;
        }

        /**
         * Returns a string representation of the algorithm, such as
         * "RSA", "DSA", or "EC".
         */
        public String toString() {
            return name;
        }

        public OBJECT_IDENTIFIER toOID() {
            return oid;
        }

        public int getPKCS11Type() {
            return pkcs11Type;
        }

        // OID for DiffieHellman, from RFC 2459 7.3.2.
        public static OBJECT_IDENTIFIER DH_OID =
            new OBJECT_IDENTIFIER( new long[] {1, 2, 840, 10046, 2, 1} );

        // From PKCS #11
        private static int CKK_RSA = 0x0;
        private static int CKK_DSA = 0x1;
        private static int CKK_DH = 0x2;
        private static int CKK_EC = 0x3;
        private static int CKK_X9_42_DH = 0x4;
        private static int CKK_KEA = 0x5;
        
        public static final Type RSA = new Type(
                OBJECT_IDENTIFIER.PKCS1.subBranch(1), "RSA", CKK_RSA );
        public static final Type DSA = new Type(
                Algorithm.ANSI_X9_ALGORITHM.subBranch(1), "DSA", CKK_DSA); 
        public static final Type EC = new Type(
            Algorithm.ANSI_X962_OID.subBranch(2).subBranch(1), "EC", CKK_EC); 
        public static final Type DiffieHellman = new Type(
                DH_OID, "DiffieHellman", CKK_DH );
                
    }
}
