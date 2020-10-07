package org.mozilla.jss.pkcs11.attrs;

import org.mozilla.jss.pkcs11.PKCS11Constants;

/**
 * CKAUsage is a collection of PKCS#11 CK_ATTRIBUTES which have common value
 * (CK_TRUE).
 */
public class CKAUsage extends CKAttribute {
    /**
     * Representation of a PKCS#11 CK_ATTRIBUTE with custom type, setting the
     * value to CK_TRUE.
     *
     * Note: it is generally recommended to use the subclasses of this class
     * instead of providing a custom value.
     */
    public CKAUsage(long type) {
        super(type);
    }

    protected native void acquireNativeResources();
    protected native void releaseNativeResources();

    /**
     * CKAEncrypt is an instance of PKCS#11 CK_ATTRIBUTE with
     * type = CKA_ENCRYPT and value CK_TRUE.
     */
    public static class Encrypt extends CKAUsage {
        public Encrypt() {
            super(PKCS11Constants.CKA_ENCRYPT);
        }
    }

    /**
     * CKADecrypt is an instance of PKCS#11 CK_ATTRIBUTE with
     * type = CKA_DECRYPT and value CK_TRUE.
     */
    public static class Decrypt extends CKAUsage {
        public Decrypt() {
            super(PKCS11Constants.CKA_DECRYPT);
        }
    }

    /**
     * CKAWrap is an instance of PKCS#11 CK_ATTRIBUTE with
     * type = CKA_WRAP and value CK_TRUE.
     */
    public static class Wrap extends CKAUsage {
        public Wrap() {
            super(PKCS11Constants.CKA_WRAP);
        }
    }

    /**
     * CKAUnwrap is an instance of PKCS#11 CK_ATTRIBUTE with
     * type = CKA_UNWRAP and value CK_TRUE.
     */
    public static class Unwrap extends CKAUsage {
        public Unwrap() {
            super(PKCS11Constants.CKA_UNWRAP);
        }
    }

    /**
     * CKASign is an instance of PKCS#11 CK_ATTRIBUTE with
     * type = CKA_SIGN and value CK_TRUE.
     */
    public static class Sign extends CKAUsage {
        public Sign() {
            super(PKCS11Constants.CKA_SIGN);
        }
    }

    /**
     * CKASignRecover is an instance of PKCS#11 CK_ATTRIBUTE with
     * type = CKA_SIGN_RECOVER and value CK_TRUE.
     */
    public static class SignRecover extends CKAUsage {
        public SignRecover() {
            super(PKCS11Constants.CKA_SIGN_RECOVER);
        }
    }

    /**
     * CKAVerify is an instance of PKCS#11 CK_ATTRIBUTE with
     * type = CKA_VERIFY and value CK_TRUE.
     */
    public static class Verify extends CKAUsage {
        public Verify() {
            super(PKCS11Constants.CKA_VERIFY);
        }
    }

    /**
     * CKAVerifyRecover is an instance of PKCS#11 CK_ATTRIBUTE with
     * type = CKA_VERIFY_RECOVER and value CK_TRUE.
     */
    public static class VerifyRecover extends CKAUsage {
        public VerifyRecover() {
            super(PKCS11Constants.CKA_VERIFY_RECOVER);
        }
    }

    /**
     * CKADerive is an instance of PKCS#11 CK_ATTRIBUTE with
     * type = CKA_DERIVE and value CK_TRUE.
     */
    public static class Derive extends CKAUsage {
        public Derive() {
            super(PKCS11Constants.CKA_DERIVE);
        }
    }
}
