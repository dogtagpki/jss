package org.mozilla.jss.crypto;

import java.util.Arrays;

import org.mozilla.jss.pkcs11.PKCS11Constants;
import org.mozilla.jss.util.NativeEnclosure;

/**
 * A KBKDF Optional Counter Parameter is a type of KBKDF Data Parameter that
 * describes the optional counter variable for Feedback and Pipeline KBKDFs.
 *
 * Note that this parameter is illegal in Counter Mode.
 */
public class KBKDFOptionalCounterParam extends KBKDFDataParameter {
    protected boolean littleEndian = false;
    protected long widthInBits = 0;

    public KBKDFOptionalCounterParam() {
        super(PKCS11Constants.CK_SP800_108_OPTIONAL_COUNTER);
    }

    public KBKDFOptionalCounterParam(boolean littleEndian, long widthInBits) throws IllegalArgumentException {
        this();
        setCounterSpec(littleEndian, widthInBits);
    }

    public void setCounterSpec(boolean littleEndian, long widthInBits) throws IllegalArgumentException {
        if (widthInBits < 8 || widthInBits > 64) {
            throw new IllegalArgumentException("Expected to have width between 8 and 64, but was " + widthInBits);
        }
        if ((widthInBits % 8) != 0) {
            throw new IllegalArgumentException("Expected width to be an even number of bytes, but was " + widthInBits);
        }

        this.littleEndian = littleEndian;
        this.widthInBits = widthInBits;
    }

    protected native void acquireNativeResources() throws Exception;
    protected native void releaseNativeResources() throws Exception;
}
