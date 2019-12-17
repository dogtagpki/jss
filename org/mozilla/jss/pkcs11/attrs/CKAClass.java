package org.mozilla.jss.pkcs11.attrs;

import org.mozilla.jss.pkcs11.PKCS11Constants;

/**
 * CKAClass is an instance of a PKCS#11 CK_ATTRIBUTE with type = CKA_CLASS.
 */
public class CKAClass extends CKAttribute {
    private long value;

    /**
     * Representation of a PKCS#11 CK_ATTRIBUTE with type CKA_CLASS and a
     * custom value.
     *
     * Note: it is generally recommended to use the subclasses of this class
     * instead of providing a custom value.
     */
    public CKAClass(long value) {
        super(PKCS11Constants.CKA_CLASS);
        setValue(value);
    }

    /**
     * Set the value of this CKA_CLASS attribute.
     */
    public void setValue(long value) {
        this.value = value;
    }

    /**
     * Get the value of this CKA_CLASS attribute.
     */
    public long getValue() {
        return value;
    }

    protected native void acquireNativeResources();
    protected native void releaseNativeResources();

    /**
     * Representation of a PKCS#11 CK_ATTRIBUTE with type CKA_CLASS and value
     * CKO_DATA.
     */
    public static class Data extends CKAClass {
        public Data() {
            super(PKCS11Constants.CKO_DATA);
        }
    }

    /**
     * Representation of a PKCS#11 CK_ATTRIBUTE with type CKA_CLASS and value
     * CKO_CERTIFICATE.
     */
    public static class Certificate extends CKAClass {
        public Certificate() {
            super(PKCS11Constants.CKO_CERTIFICATE);
        }
    }

    /**
     * Representation of a PKCS#11 CK_ATTRIBUTE with type CKA_CLASS and value
     * CKO_PUBLIC_KEY.
     */
    public static class PublicKey extends CKAClass {
        public PublicKey() {
            super(PKCS11Constants.CKO_PUBLIC_KEY);
        }
    }

    /**
     * Representation of a PKCS#11 CK_ATTRIBUTE with type CKA_CLASS and value
     * CKO_PRIVATE_KEY.
     */
    public static class PrivateKey extends CKAClass {
        public PrivateKey() {
            super(PKCS11Constants.CKO_PRIVATE_KEY);
        }
    }

    /**
     * Representation of a PKCS#11 CK_ATTRIBUTE with type CKA_CLASS and value
     * CKO_SECRET_KEY.
     */
    public static class SecretKey extends CKAClass {
        public SecretKey() {
            super(PKCS11Constants.CKO_SECRET_KEY);
        }
    }

    /**
     * Representation of a PKCS#11 CK_ATTRIBUTE with type CKA_CLASS and value
     * CKO_HW_FEATURE.
     */
    public static class HWFeature extends CKAClass {
        public HWFeature() {
            super(PKCS11Constants.CKO_HW_FEATURE);
        }
    }

    /**
     * Representation of a PKCS#11 CK_ATTRIBUTE with type CKA_CLASS and value
     * CKO_DOMAIN_PARAMETERS.
     */
    public static class DomainParameters extends CKAClass {
        public DomainParameters() {
            super(PKCS11Constants.CKO_DOMAIN_PARAMETERS);
        }
    }

    /**
     * Representation of a PKCS#11 CK_ATTRIBUTE with type CKA_CLASS and value
     * CKO_MECHANISM.
     */
    public static class Mechanism extends CKAClass {
        public Mechanism() {
            super(PKCS11Constants.CKO_MECHANISM);
        }
    }
}
