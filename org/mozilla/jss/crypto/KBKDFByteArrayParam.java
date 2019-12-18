package org.mozilla.jss.crypto;

import java.util.Arrays;

import org.mozilla.jss.util.NativeEnclosure;
import org.mozilla.jss.pkcs11.PKCS11Constants;

/**
 * A KBKDF Byte Array Parameter is a type of KBKDF Data Parameter that
 * contains a single byte array that gets passed to the KBKDF to be inserted
 * into the PRF input stream.
 */
public class KBKDFByteArrayParam extends KBKDFDataParameter {
    private byte[] data;

    public KBKDFByteArrayParam() {
        super(PKCS11Constants.CK_SP800_108_BYTE_ARRAY);
    }

    public KBKDFByteArrayParam(byte[] data) throws IllegalArgumentException {
        this();
        setByteArray(data);
    }

    public void setByteArray(byte[] data) throws IllegalArgumentException {
        if (data == null) {
            throw new IllegalArgumentException("Expected non-null byte array!");
        }

        this.data = Arrays.copyOf(data, data.length);
    }

    /**
     * Zero out the copied contents of the byte array.
     *
     * Call this method when the contents of this byte array parameter are
     * sensitive and they're done being used. Note that this isn't called
     * during close() as a given byte array parameter may be used multiple
     * times in different KBKDF calls.
     */
    public void zeroByteArray() {
        if (data == null) {
            return;
        }

        for (int i = 0; i < data.length; i++) {
            data[i] = 0;
        }
    }

    protected void acquireNativeResources() throws Exception {
        if (data == null || data.length == 0) {
            String msg = "Expected non-null byte array in ";
            msg += "KBKDFByteArrayParam but was null! Call setByteArray ";
            msg += "to provide a byte array.";
            throw new RuntimeException(msg);
        }

        acquireNativeResourcesInternal();
    }

    protected void releaseNativeResources() throws Exception {
        releaseNativeResourcesInternal();
    }

    private native void acquireNativeResourcesInternal() throws Exception;
    private native void releaseNativeResourcesInternal() throws Exception;
}
