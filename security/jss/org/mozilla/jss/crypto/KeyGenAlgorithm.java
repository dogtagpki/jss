/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.crypto;

import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;
import java.util.Hashtable;
import java.security.NoSuchAlgorithmException;

/**
 * Algorithms that can be used for generating symmetric keys.
 */
public class KeyGenAlgorithm extends Algorithm {

    protected static interface KeyStrengthValidator {
        public boolean isValidKeyStrength(int strength);
    }

    protected static class FixedKeyStrengthValidator
            implements KeyStrengthValidator
    {
        private int strength;

        public FixedKeyStrengthValidator(int strength) {
            this.strength = strength;
        }

        public boolean isValidKeyStrength(int strength) {
            return this.strength == strength;
        }
    }

    protected KeyGenAlgorithm(int oidTag, String name,
            KeyStrengthValidator keyStrengthValidator,
            OBJECT_IDENTIFIER oid, Class paramClass)
    {
        super(oidTag, name, oid, paramClass);
        this.keyStrengthValidator = keyStrengthValidator;
        if(oid!=null) {
            oidMap.put(oid, this);
        }
    }

    ///////////////////////////////////////////////////////////////////////
    // OIDs
    ///////////////////////////////////////////////////////////////////////
    private static final OBJECT_IDENTIFIER PKCS5 = OBJECT_IDENTIFIER.PKCS5;
    private static final OBJECT_IDENTIFIER PKCS12_PBE =
            OBJECT_IDENTIFIER.PKCS12.subBranch(1);

    ///////////////////////////////////////////////////////////////////////
    // OID mapping
    ///////////////////////////////////////////////////////////////////////
    private static Hashtable oidMap = new Hashtable();

    public static KeyGenAlgorithm fromOID(OBJECT_IDENTIFIER oid)
        throws NoSuchAlgorithmException
    {
        Object alg = oidMap.get(oid);
        if( alg == null ) {
            throw new NoSuchAlgorithmException(oid.toString());
        } else {
            return (KeyGenAlgorithm) alg;
        }
    }

    private KeyStrengthValidator keyStrengthValidator;

    /**
     * Returns <code>true</code> if the given strength is valid for this
     * key generation algorithm. Note that PBE algorithms require
     * PBEParameterSpecs rather than strengths.  It is the responsibility
     * of the caller to verify this.
     */
    public boolean isValidStrength(int strength) {
        return keyStrengthValidator.isValidKeyStrength(strength);
    }

    //////////////////////////////////////////////////////////////
    public static final KeyGenAlgorithm
    DES = new KeyGenAlgorithm(CKM_DES_KEY_GEN, "DES",
            new FixedKeyStrengthValidator(56), null, null);

    //////////////////////////////////////////////////////////////
    public static final KeyGenAlgorithm
    DES3 = new KeyGenAlgorithm(CKM_DES3_KEY_GEN, "DESede",
            new FixedKeyStrengthValidator(168), null, null);

    public static final KeyGenAlgorithm
    DESede = DES3;

    //////////////////////////////////////////////////////////////
    public static final KeyGenAlgorithm
    RC4 = new KeyGenAlgorithm(CKM_RC4_KEY_GEN, "RC4",
            new KeyStrengthValidator() {
                public boolean isValidKeyStrength(int strength) {
                    return true;
                }
            }, null, null);

    //////////////////////////////////////////////////////////////
    public static final KeyGenAlgorithm
    PBA_SHA1_HMAC = new KeyGenAlgorithm(
        CKM_PBA_SHA1_WITH_SHA1_HMAC,
            "PBA/SHA1/HMAC", new FixedKeyStrengthValidator(160),
            null, PBEKeyGenParams.class );

    //////////////////////////////////////////////////////////////
    public static final KeyGenAlgorithm
    AES = new KeyGenAlgorithm(CKM_AES_KEY_GEN, "AES", 
            new KeyStrengthValidator() {
                public boolean isValidKeyStrength(int strength) {
                    return strength==128 || strength==192 || strength==256;
                }
            }, null, null);
    //////////////////////////////////////////////////////////////
    public static final KeyGenAlgorithm
    RC2 = new KeyGenAlgorithm(CKM_RC2_KEY_GEN, "RC2", 
            new KeyStrengthValidator() {
                public boolean isValidKeyStrength(int strength) {
                    // 1 byte - 128 bytes
                    return strength>=8 && strength <= (128*8);
                }
            }, null, null);
}
