package org.mozilla.jss.pkcs11.attrs;

import org.mozilla.jss.pkcs11.PKCS11Constants;

/**
 * CKAClass is an instance of a PKCS#11 CK_ATTRIBUTE with type = CKA_CLASS.
 */
public class CKAValueLen extends CKAttribute {
    private long length = 0;

    /**
     * Representation of a PKCS#11 CK_ATTRIBUTE with type CKA_VALUE_LEN and
     * default length for the key type.
     *
     * Note that when key type is not specified and/or that mechanism lacks a
     * default size, the corresponding PKCS#11 call will error out.
     */
    public CKAValueLen() {
        super(PKCS11Constants.CKA_VALUE_LEN);
    }

    /**
     * Representation of a PKCS#11 CK_ATTRIBUTE with type CKA_VALUE_LEN and a
     * specified length.
     */
    public CKAValueLen(long length) {
        this();
        setLength(length);
    }

    /**
     * Set the length specified by this CKA_VALUE_LEN attribute.
     */
    public void setLength(long length) {
        this.length = length;
    }

    /**
     * Get the length of this CKA_VALUE_LEN attribute.
     */
    public long getLength() {
        return length;
    }

    protected native void acquireNativeResources();
    protected native void releaseNativeResources();
}
