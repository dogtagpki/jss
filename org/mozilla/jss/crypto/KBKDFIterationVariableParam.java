package org.mozilla.jss.crypto;

import java.util.Arrays;

import org.mozilla.jss.pkcs11.PKCS11Constants;
import org.mozilla.jss.util.NativeEnclosure;

/**
 * A KBKDF Iteration Variable Parameter is a type of KBKDF Data Parameter that
 * either references the counter variable or otherwise is a pointer to the
 * output of the previous PRF invocation.
 *
 * Note that in when used with Counter Mode KBKDF, this parameter must be
 * initialized with the two argument constructor. In other KBKDF modes,
 * in particular, Feedback and Pipeline modes, this must be initialized with
 * the no argument constructor. To add an optional counter to the PRF input
 * stream under Feedback and Pipeline modes, use KBKDFOptionalCounterParam
 * instead.
 */
public class KBKDFIterationVariableParam extends KBKDFDataParameter {
    protected boolean littleEndian = false;
    protected long widthInBits = -1;

    public KBKDFIterationVariableParam() {
        super(PKCS11Constants.CK_SP800_108_ITERATION_VARIABLE);
    }

    public KBKDFIterationVariableParam(boolean littleEndian, long widthInBits) throws IllegalArgumentException {
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
