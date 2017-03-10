/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.crypto;

import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;
import java.security.NoSuchAlgorithmException;

/**
 * Represents a cryptographic algorithm.
 * @see EncryptionAlgorithm
 * @see SignatureAlgorithm
 */
public class Algorithm {

    private Algorithm() { }

    /**
     * @param oidIndex Index of the oid that this algorithm represents.
     * @param name A String representation of the Algorithm.
     */
    protected Algorithm(int oidIndex, String name) {
        this.oidIndex = oidIndex;
        this.name = name;
    }

    /**
     * @param oidIndex Index of the oid that this algorithm represents.
     * @param name A String representation of the Algorithm.
     * @param oid The object identifier for this Algorithm.
     */
    protected Algorithm(int oidIndex, String name, OBJECT_IDENTIFIER oid) {
        this(oidIndex, name);
        this.oid = oid;
    }

    protected Algorithm(int oidIndex, String name, OBJECT_IDENTIFIER oid,
                        Class paramClass)
    {
        this(oidIndex, name, oid);
        if( paramClass == null ) {
            this.parameterClasses = new Class[0];
        } else {
            this.parameterClasses = new Class[1];
            this.parameterClasses[0] = paramClass;
        }
    }

    protected Algorithm(int oidIndex, String name, OBJECT_IDENTIFIER oid,
                        Class []paramClasses)
    {
        this(oidIndex, name, oid);
        if( paramClasses != null ) {
            this.parameterClasses = paramClasses;
        }
    }

    /**
     * Returns a String representation of the algorithm.
     */
    public String toString() {
        return name;
    }

    /**
     * Returns the object identifier for this algorithm.
     * @exception NoSuchAlgorithmException If no OID is registered for this
     *      algorithm.
     */
    public OBJECT_IDENTIFIER toOID() throws NoSuchAlgorithmException {
        if( oid == null ) {
            throw new NoSuchAlgorithmException();
        } else {
            return oid;
        }
    }

    /**
     * The type of parameter that this algorithm expects.  Returns
     *   <code>null</code> if this algorithm does not take any parameters.
     * If the algorithm can accept more than one type of parameter,
     *   this method returns only one of them. It is better to call
     *   <tt>getParameterClasses()</tt>.
     * @deprecated Call <tt>getParameterClasses()</tt> instead.
     */
    public Class getParameterClass() {
        if( parameterClasses.length == 0) {
            return null;
        } else {
            return parameterClasses[0];
        }
    }

    /**
     * The types of parameter that this algorithm expects.  Returns
     *   <code>null</code> if this algorithm does not take any parameters.
     */
    public Class[] getParameterClasses() {
        return (Class[]) parameterClasses.clone();
    }

    /**
     * Returns <tt>true</tt> if the given Object can be used as a parameter
     * for this algorithm.
     * <p>If <tt>null</tt> is passed in, this method will return <tt>true</tt>
     *      if this algorithm takes no parameters, and <tt>false</tt>
     *      if this algorithm does take parameters.
     */
    public boolean isValidParameterObject(Object o) {
        if( o == null ) {
            return (parameterClasses.length == 0);
        }
        if( parameterClasses.length == 0 ){
            return false;
        }
        Class c = o.getClass();
        for( int i = 0; i < parameterClasses.length; ++i) {
            if( c.equals( parameterClasses[i] ) ) {
                return true;
            }
        }
        return false;
    }

    /**
     * Index into the SECOidTag array in Algorithm.c.
     */
    protected int oidIndex;
    String name;
    protected OBJECT_IDENTIFIER oid;
    private Class[] parameterClasses=new Class[0];

    //////////////////////////////////////////////////////////////
    // Algorithm OIDs
    //////////////////////////////////////////////////////////////
    static final OBJECT_IDENTIFIER ANSI_X9_ALGORITHM = 
        new OBJECT_IDENTIFIER( new long[] { 1, 2, 840, 10040, 4 } );
    static final OBJECT_IDENTIFIER ANSI_X962_OID = 
        new OBJECT_IDENTIFIER( new long[] { 1, 2, 840, 10045 } );

    // Algorithm indices.  These must be kept in sync with the
    // algorithm array in Algorithm.c.
    protected static final short SEC_OID_PKCS1_MD2_WITH_RSA_ENCRYPTION=0;
    protected static final short SEC_OID_PKCS1_MD5_WITH_RSA_ENCRYPTION=1;
    protected static final short SEC_OID_PKCS1_SHA1_WITH_RSA_ENCRYPTION=2;
    protected static final short SEC_OID_ANSIX9_DSA_SIGNATURE_WITH_SHA1_DIGEST=3;
    protected static final short SEC_OID_PKCS1_RSA_ENCRYPTION=4;
    protected static final short CKM_RSA_PKCS_KEY_PAIR_GEN=5;
    protected static final short CKM_DSA_KEY_PAIR_GEN=6;
    protected static final short SEC_OID_ANSIX9_DSA_SIGNATURE=7;
    protected static final short SEC_OID_RC4=8;
    protected static final short SEC_OID_DES_ECB=9;
    protected static final short SEC_OID_DES_CBC=10;
    protected static final short CKM_DES_CBC_PAD=11;
    protected static final short CKM_DES3_ECB=12;
    protected static final short SEC_OID_DES_EDE3_CBC=13;
    protected static final short CKM_DES3_CBC_PAD=14;
    protected static final short CKM_DES_KEY_GEN=15;
    protected static final short CKM_DES3_KEY_GEN=16;
    protected static final short CKM_RC4_KEY_GEN=17;

    protected static final short SEC_OID_PKCS5_PBE_WITH_MD2_AND_DES_CBC=18;
    protected static final short SEC_OID_PKCS5_PBE_WITH_MD5_AND_DES_CBC=19;
    protected static final short SEC_OID_PKCS5_PBE_WITH_SHA1_AND_DES_CBC=20;
    protected static final short
        SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_128_BIT_RC4=21;
    protected static final short
        SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_40_BIT_RC4=22;
    protected static final short
        SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_3KEY_TRIPLE_DES_CBC=23;
    protected static final short SEC_OID_MD2=24;
    protected static final short SEC_OID_MD5=25;
    protected static final short SEC_OID_SHA1=26;
    protected static final short CKM_SHA_1_HMAC=27;
    protected static final short
        SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_128_BIT_RC2_CBC=28;
    protected static final short
        SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_40_BIT_RC2_CBC=29;
    protected static final short SEC_OID_RC2_CBC=30;
    protected static final short CKM_PBA_SHA1_WITH_SHA1_HMAC=31;

    // AES
    protected static final short CKM_AES_KEY_GEN=32;
    protected static final short CKM_AES_ECB=33;
    protected static final short CKM_AES_CBC=34;
    protected static final short CKM_AES_CBC_PAD=35;
    protected static final short CKM_RC2_CBC_PAD=36;
    protected static final short CKM_RC2_KEY_GEN=37;
    //FIPS 180-2
    protected static final short SEC_OID_SHA256=38;
    protected static final short SEC_OID_SHA384=39;
    protected static final short SEC_OID_SHA512=40;
    protected static final short SEC_OID_PKCS1_SHA256_WITH_RSA_ENCRYPTION=41;
    protected static final short SEC_OID_PKCS1_SHA384_WITH_RSA_ENCRYPTION=42;
    protected static final short SEC_OID_PKCS1_SHA512_WITH_RSA_ENCRYPTION=43;
    protected static final short SEC_OID_ANSIX962_EC_PUBLIC_KEY=44;
    protected static final short SEC_OID_ANSIX962_ECDSA_SHA1_SIGNATURE=45;
    protected static final short CKM_EC_KEY_PAIR_GEN=46;
    protected static final short SEC_OID_ANSIX962_ECDSA_SHA256_SIGNATURE=47;
    protected static final short SEC_OID_ANSIX962_ECDSA_SHA384_SIGNATURE=48;
    protected static final short SEC_OID_ANSIX962_ECDSA_SHA512_SIGNATURE=49;

    protected static final short SEC_OID_HMAC_SHA256=50;
    protected static final short SEC_OID_HMAC_SHA384=51;
    protected static final short SEC_OID_HMAC_SHA512=52;

    //PKCS5 V2
    protected static final short SEC_OID_PKCS5_PBKDF2=53;
    protected static final short SEC_OID_PKCS5_PBES2=54;
    protected static final short SEC_OID_PKCS5_PBMAC1=55;
    protected static final short SEC_OID_ANSIX962_ECDSA_SIGNATURE_SPECIFIED_DIGEST=56;
    protected static final short CKM_NSS_AES_KEY_WRAP=57;
    protected static final short CKM_NSS_AES_KEY_WRAP_PAD=58;
}
