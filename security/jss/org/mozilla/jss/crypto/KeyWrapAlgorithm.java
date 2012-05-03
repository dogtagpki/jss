/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.crypto;

import java.util.Hashtable;
import java.security.NoSuchAlgorithmException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.RC2ParameterSpec;

/**
 *
 */
public class KeyWrapAlgorithm extends Algorithm {
    protected KeyWrapAlgorithm(int oidTag, String name, Class paramClass,
        boolean padded, int blockSize) {
        super(oidTag, name, null, paramClass);
        this.padded = padded;
        this.blockSize = blockSize;
        if( name != null ) {
            nameMap.put(name.toLowerCase(), this);
        }
    }

    protected KeyWrapAlgorithm(int oidTag, String name, Class []paramClasses,
        boolean padded, int blockSize) {
        super(oidTag, name, null, paramClasses);
        this.padded = padded;
        this.blockSize = blockSize;
        if( name != null ) {
            nameMap.put(name.toLowerCase(), this);
        }
    }

    private boolean padded;
    private int blockSize;

    private static Hashtable nameMap = new Hashtable();

    public static KeyWrapAlgorithm fromString(String name)
            throws NoSuchAlgorithmException
    {
        Object alg = nameMap.get( name.toLowerCase() );
        if( alg == null ) {
            throw new NoSuchAlgorithmException();
        } else {
            return (KeyWrapAlgorithm) alg;
        }
    }

    public boolean isPadded() {
        return padded;
    }

    public int getBlockSize() {
        return blockSize;
    }

    private static Class[] IVParameterSpecClasses = null;
    static {
        IVParameterSpecClasses = new Class[2];
        IVParameterSpecClasses[0] = IVParameterSpec.class;
        IVParameterSpecClasses[1] = IvParameterSpec.class;
    }

    public static final KeyWrapAlgorithm
    DES_ECB = new KeyWrapAlgorithm(SEC_OID_DES_ECB, "DES/ECB", (Class) null,
        false, 8);

    public static final KeyWrapAlgorithm
    DES_CBC = new KeyWrapAlgorithm(SEC_OID_DES_CBC, "DES/CBC",
                        IVParameterSpecClasses, false, 8);

    public static final KeyWrapAlgorithm
    DES_CBC_PAD = new KeyWrapAlgorithm(CKM_DES_CBC_PAD, "DES/CBC/Pad",
                        IVParameterSpecClasses, true, 8);

    public static final KeyWrapAlgorithm
    DES3_ECB = new KeyWrapAlgorithm(CKM_DES3_ECB, "DES3/ECB", (Class)null,
        false, 8);

    public static final KeyWrapAlgorithm
    DES3_CBC = new KeyWrapAlgorithm(SEC_OID_DES_EDE3_CBC, "DES3/CBC",
                        IVParameterSpecClasses, false, 8);

    public static final KeyWrapAlgorithm
    DES3_CBC_PAD = new KeyWrapAlgorithm(CKM_DES3_CBC_PAD, "DES3/CBC/Pad",
                        IVParameterSpecClasses, true, 8);

    public static final KeyWrapAlgorithm
    RSA = new KeyWrapAlgorithm(SEC_OID_PKCS1_RSA_ENCRYPTION, "RSA",
            (Class) null, false, 0);

    public static final KeyWrapAlgorithm
    PLAINTEXT = new KeyWrapAlgorithm(0, "Plaintext", (Class) null,
            false, 0);

    public static final KeyWrapAlgorithm
    AES_ECB = new KeyWrapAlgorithm(CKM_AES_ECB, "AES/ECB/NoPadding",
        (Class) null, false, 16);

    public static final KeyWrapAlgorithm
    AES_CBC = new KeyWrapAlgorithm(CKM_AES_CBC, "AES/CBC/NoPadding",
                        IVParameterSpecClasses, false, 16);

    public static final KeyWrapAlgorithm
    AES_CBC_PAD = new KeyWrapAlgorithm(CKM_AES_CBC_PAD, "AES/CBC/PKCS5Padding",
                        IVParameterSpecClasses, true, 16);

    public static final KeyWrapAlgorithm
    RC2_CBC_PAD = new KeyWrapAlgorithm(CKM_RC2_CBC_PAD, "RC2/CBC/PKCS5Padding",
                        RC2ParameterSpec.class, true, 8);
}
