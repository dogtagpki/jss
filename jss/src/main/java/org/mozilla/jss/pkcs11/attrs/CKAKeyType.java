package org.mozilla.jss.pkcs11.attrs;

import org.mozilla.jss.pkcs11.PKCS11Constants;

/**
 * CKA_KEY_TYPE is an instance of a PKCS#11 CK_ATTRIBUTE with
 * type = CKA_KEY_TYPE.
 */
public class CKAKeyType extends CKAttribute {
    private long value;

    /**
     * Representation of a PKCS#11 CK_ATTRIBUTE with type CKA_KEY_TYPE and a
     * custom value.
     *
     * Note: it is generally recommended to use the subclasses of this class
     * instead of providing a custom value.
     */
    public CKAKeyType(long value) {
        super(PKCS11Constants.CKA_KEY_TYPE);
        setValue(value);
    }

    /**
     * Set the value of this CKA_KEY_TYPE attribute.
     */
    public void setValue(long value) {
        this.value = value;
    }

    /**
     * Get the value of this CKA_KEY_TYPE attribute.
     */
    public long getValue() {
        return value;
    }

    protected native void acquireNativeResources();
    protected native void releaseNativeResources();

    /**
     * Representation of a PKCS#11 CK_ATTRIBUTE with type CKA_KEY_TYPE and
     * value CKK_RSA.
     */
    public static class RSA extends CKAKeyType {
        public RSA() {
            super(PKCS11Constants.CKK_RSA);
        }
    }

    /**
     * Representation of a PKCS#11 CK_ATTRIBUTE with type CKA_KEY_TYPE and
     * value CKK_DSA.
     */
    public static class DSA extends CKAKeyType {
        public DSA() {
            super(PKCS11Constants.CKK_DSA);
        }
    }

    /**
     * Representation of a PKCS#11 CK_ATTRIBUTE with type CKA_KEY_TYPE and
     * value CKK_DH.
     */
    public static class DH extends CKAKeyType {
        public DH() {
            super(PKCS11Constants.CKK_DH);
        }
    }

    /**
     * Representation of a PKCS#11 CK_ATTRIBUTE with type CKA_KEY_TYPE and
     * value CKK_ECDSA.
     */
    public static class ECDSA extends CKAKeyType {
        public ECDSA() {
            super(PKCS11Constants.CKK_ECDSA);
        }
    }

    /**
     * Representation of a PKCS#11 CK_ATTRIBUTE with type CKA_KEY_TYPE and
     * value CKK_EC.
     */
    public static class EC extends CKAKeyType {
        public EC() {
            super(PKCS11Constants.CKK_EC);
        }
    }

    /**
     * Representation of a PKCS#11 CK_ATTRIBUTE with type CKA_KEY_TYPE and
     * value CKK_X9_42_DH.
     */
    public static class X9_42_DH extends CKAKeyType {
        public X9_42_DH() {
            super(PKCS11Constants.CKK_X9_42_DH);
        }
    }

    /**
     * Representation of a PKCS#11 CK_ATTRIBUTE with type CKA_KEY_TYPE and
     * value CKK_KEA.
     */
    public static class KEA extends CKAKeyType {
        public KEA() {
            super(PKCS11Constants.CKK_KEA);
        }
    }

    /**
     * Representation of a PKCS#11 CK_ATTRIBUTE with type CKA_KEY_TYPE and
     * value CKK_GENERIC_SECRET.
     */
    public static class GenericSecret extends CKAKeyType {
        public GenericSecret() {
            super(PKCS11Constants.CKK_GENERIC_SECRET);
        }
    }

    /**
     * Representation of a PKCS#11 CK_ATTRIBUTE with type CKA_KEY_TYPE and
     * value CKK_RC2.
     */
    public static class RC2 extends CKAKeyType {
        public RC2() {
            super(PKCS11Constants.CKK_RC2);
        }
    }

    /**
     * Representation of a PKCS#11 CK_ATTRIBUTE with type CKA_KEY_TYPE and
     * value CKK_RC4.
     */
    public static class RC4 extends CKAKeyType {
        public RC4() {
            super(PKCS11Constants.CKK_RC4);
        }
    }

    /**
     * Representation of a PKCS#11 CK_ATTRIBUTE with type CKA_KEY_TYPE and
     * value CKK_DES.
     */
    public static class DES extends CKAKeyType {
        public DES() {
            super(PKCS11Constants.CKK_DES);
        }
    }

    /**
     * Representation of a PKCS#11 CK_ATTRIBUTE with type CKA_KEY_TYPE and
     * value CKK_DES2.
     */
    public static class DES2 extends CKAKeyType {
        public DES2() {
            super(PKCS11Constants.CKK_DES2);
        }
    }

    /**
     * Representation of a PKCS#11 CK_ATTRIBUTE with type CKA_KEY_TYPE and
     * value CKK_DES3.
     */
    public static class DES3 extends CKAKeyType {
        public DES3() {
            super(PKCS11Constants.CKK_DES3);
        }
    }

    /**
     * Representation of a PKCS#11 CK_ATTRIBUTE with type CKA_KEY_TYPE and
     * value CKK_CAST.
     */
    public static class CAST extends CKAKeyType {
        public CAST() {
            super(PKCS11Constants.CKK_CAST);
        }
    }

    /**
     * Representation of a PKCS#11 CK_ATTRIBUTE with type CKA_KEY_TYPE and
     * value CKK_CAST3.
     */
    public static class CAST3 extends CKAKeyType {
        public CAST3() {
            super(PKCS11Constants.CKK_CAST3);
        }
    }

    /**
     * Representation of a PKCS#11 CK_ATTRIBUTE with type CKA_KEY_TYPE and
     * value CKK_CAST5.
     */
    public static class CAST5 extends CKAKeyType {
        public CAST5() {
            super(PKCS11Constants.CKK_CAST5);
        }
    }

    /**
     * Representation of a PKCS#11 CK_ATTRIBUTE with type CKA_KEY_TYPE and
     * value CKK_CAST128.
     */
    public static class CAST128 extends CKAKeyType {
        public CAST128() {
            super(PKCS11Constants.CKK_CAST128);
        }
    }

    /**
     * Representation of a PKCS#11 CK_ATTRIBUTE with type CKA_KEY_TYPE and
     * value CKK_RC5.
     */
    public static class RC5 extends CKAKeyType {
        public RC5() {
            super(PKCS11Constants.CKK_RC5);
        }
    }

    /**
     * Representation of a PKCS#11 CK_ATTRIBUTE with type CKA_KEY_TYPE and
     * value CKK_IDEA.
     */
    public static class IDEA extends CKAKeyType {
        public IDEA() {
            super(PKCS11Constants.CKK_IDEA);
        }
    }

    /**
     * Representation of a PKCS#11 CK_ATTRIBUTE with type CKA_KEY_TYPE and
     * value CKK_SKIPJACK.
     */
    public static class Skipjack extends CKAKeyType {
        public Skipjack() {
            super(PKCS11Constants.CKK_SKIPJACK);
        }
    }

    /**
     * Representation of a PKCS#11 CK_ATTRIBUTE with type CKA_KEY_TYPE and
     * value CKK_BATON.
     */
    public static class BATON extends CKAKeyType {
        public BATON() {
            super(PKCS11Constants.CKK_BATON);
        }
    }

    /**
     * Representation of a PKCS#11 CK_ATTRIBUTE with type CKA_KEY_TYPE and
     * value CKK_JUNIPER.
     */
    public static class JUNIPER extends CKAKeyType {
        public JUNIPER() {
            super(PKCS11Constants.CKK_JUNIPER);
        }
    }

    /**
     * Representation of a PKCS#11 CK_ATTRIBUTE with type CKA_KEY_TYPE and
     * value CKK_CDMF.
     */
    public static class CDMF extends CKAKeyType {
        public CDMF() {
            super(PKCS11Constants.CKK_CDMF);
        }
    }

    /**
     * Representation of a PKCS#11 CK_ATTRIBUTE with type CKA_KEY_TYPE and
     * value CKK_AES.
     */
    public static class AES extends CKAKeyType {
        public AES() {
            super(PKCS11Constants.CKK_AES);
        }
    }

    /**
     * Representation of a PKCS#11 CK_ATTRIBUTE with type CKA_KEY_TYPE and
     * value CKK_BLOWFISH.
     */
    public static class Blowfish extends CKAKeyType {
        public Blowfish() {
            super(PKCS11Constants.CKK_BLOWFISH);
        }
    }

    /**
     * Representation of a PKCS#11 CK_ATTRIBUTE with type CKA_KEY_TYPE and
     * value CKK_TWOFISH.
     */
    public static class Twofish extends CKAKeyType {
        public Twofish() {
            super(PKCS11Constants.CKK_TWOFISH);
        }
    }

    /**
     * Representation of a PKCS#11 CK_ATTRIBUTE with type CKA_KEY_TYPE and
     * value CKK_CAMELLIA.
     */
    public static class Camellia extends CKAKeyType {
        public Camellia() {
            super(PKCS11Constants.CKK_CAMELLIA);
        }
    }

    /**
     * Representation of a PKCS#11 CK_ATTRIBUTE with type CKA_KEY_TYPE and
     * value CKK_SEED.
     */
    public static class Seed extends CKAKeyType {
        public Seed() {
            super(PKCS11Constants.CKK_SEED);
        }
    }
}
