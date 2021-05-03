package org.mozilla.jss.pkcs11.attrs;

import org.mozilla.jss.util.NativeEnclosure;

/**
 * A CKAttribute is an instance of PKCS#11 CK_ATTRIBUTE.
 *
 * Each CK_ATTRIBUTE contains three parts:
 *  1. A type (type),
 *  2. A pointer to a value (pValue),
 *  3. The size of said value (ulValueLen).
 *
 * In the Java layer, CKAttribute has a member "type" to contain the type
 * of the CK_ATTRIBUTE. It takes on values from PKCS11Constants (pkcs11t.h
 * and pkcs11n.h) with prefix "CKA_". The two NativeEnclosure fields,
 * mPointer and mPointerSize wrap a pointer to the underlying CK_ATTRIBUTE
 * and its size respectively. They get allocated when open() is called, and
 * freed when close() is called.
 *
 * The value (numbers 2 and 3 above) get determined by the extending type,
 * and its corresponding native methods. Some use statically allocated values,
 * like CKAUsage's classes. Others are dynamically allocated pointers, such as
 * when referring to CK_ULONG values (as with CKAValueLen for instance).
 */
public abstract class CKAttribute extends NativeEnclosure {
    public long type;

    public CKAttribute(long type) {
        this.type = type;
    }
}
