package org.mozilla.jss.crypto;

import java.lang.IllegalArgumentException;
import java.security.InvalidKeyException;
import java.util.Arrays;
import java.util.ArrayList;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

import org.mozilla.jss.pkcs11.attrs.CKAttribute;
import org.mozilla.jss.util.NativeEnclosure;

/**
 * Class for supporting additional derived keys from PKCS#11 v3.0's
 * SP800-108 KBKDF implementation.
 */
public class KBKDFDerivedKey extends NativeEnclosure {
    private CKAttribute[] attrs;
    private long handle;

    public KBKDFDerivedKey() {}

    public KBKDFDerivedKey(CKAttribute[] attrs) throws IllegalArgumentException {
        setAttributes(attrs);
    }

    public void setAttributes(CKAttribute[] attrs) throws IllegalArgumentException {
        if (attrs == null) {
            String msg = "Expected populated array of CKAttributes, but ";
            msg += "was null.";
            throw new IllegalArgumentException(msg);
        }
        this.attrs = attrs;
    }

    public void addAttribute(CKAttribute attr) throws IllegalArgumentException {
        if (attr == null) {
            String msg = "Expected non-null CKAttribute, but was null.";
            throw new IllegalArgumentException(msg);
        }

        ArrayList<CKAttribute> ck_attrs;
        if (attrs == null) {
            ck_attrs = new ArrayList<CKAttribute>(1);
        } else {
            ck_attrs = new ArrayList<CKAttribute>(Arrays.asList(attrs));
        }
        ck_attrs.add(attr);

        this.attrs = ck_attrs.toArray(new CKAttribute[ck_attrs.size()]);
    }

    protected void acquireNativeResources() throws Exception {
        if (attrs == null) {
            String msg = "Expected non-null attributes when trying to ";
            msg += "acquire native resources. Call setAttributes(...) ";
            msg += "or addAttribute(...) before calling open().";

            throw new IllegalArgumentException(msg);
        }

        for (CKAttribute attr : attrs) {
            attr.open();
        }

        acquireNativeResourcesInternal();
    }

    protected void releaseNativeResources() throws Exception {
        if (attrs != null) {
            for (CKAttribute attr : attrs) {
                attr.close();
            }
        }

        releaseNativeResourcesInternal();
    }

    public SecretKey getKey(SecretKey parent, long mech, boolean temporary) throws Exception {
        SecretKeyFactory skf = SecretKeyFactory.getInstance(parent.getAlgorithm(), "Mozilla-JSS");
        SecretKey translated = skf.translateKey(parent);
        SymmetricKey unwrapped = null;

        if (translated instanceof SymmetricKey) {
            unwrapped = (SymmetricKey)translated;
        } else if (translated instanceof SecretKeyFacade) {
            unwrapped = ((SecretKeyFacade)translated).key;
        } else {
            String msg = "Expected key to become an instance of ";
            msg += "org.mozilla.jss.crypto.SymmetricKey or ";
            msg += "org.mozilla.jss.crypto.SecretKeyFacade after ";
            msg += "translation, but got: ";
            msg += translated.getClass().getName();

            throw new InvalidKeyException(msg);
        }

        SymmetricKey key = getKeyFromHandle(unwrapped, mech, temporary);

        return new SecretKeyFacade(key);
    }

    private native SymmetricKey getKeyFromHandle(SymmetricKey parentKey, long mech, boolean temporary) throws Exception;

    protected native void acquireNativeResourcesInternal() throws Exception;
    protected native void releaseNativeResourcesInternal() throws Exception;
}
