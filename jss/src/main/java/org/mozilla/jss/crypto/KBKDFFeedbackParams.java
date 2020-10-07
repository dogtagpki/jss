package org.mozilla.jss.crypto;

import java.util.Arrays;
import java.security.InvalidKeyException;
import javax.crypto.SecretKey;

import org.mozilla.jss.pkcs11.PKCS11Constants;

public class KBKDFFeedbackParams extends KBKDFParameterSpec {
    private byte[] initial_value;

    public KBKDFFeedbackParams() {}

    public void setInitialValue(byte[] iv) throws IllegalArgumentException {
        if (iv == null) {
            String msg = "Expected non-null initial value!";
            throw new IllegalArgumentException(msg);
        }

        this.initial_value = Arrays.copyOf(iv, iv.length);
    }

    /**
     * Zero out the copiend contents of the initial value.
     *
     * Call this method when the contents of the initial value are sensitive
     * and they're done being used. Note that this isn't called during
     * close() as a given KBKDFParameterSpec instance may be reused, updating
     * relevant parameters between calls.
     */
    public void zeroInitialValue() {
        if (initial_value == null) {
            return;
        }

        for (int i = 0; i < initial_value.length; i++) {
            initial_value[i] = 0;
        }
    }

    protected void validateParameters() throws IllegalArgumentException {
        if (prfKey == null) {
            String msg = "Required parameter KDF key was never set.";
            throw new IllegalArgumentException(msg);
        }

        if (prf != PKCS11Constants.CKM_SHA_1_HMAC &&
                prf != PKCS11Constants.CKM_SHA256_HMAC &&
                prf != PKCS11Constants.CKM_SHA384_HMAC &&
                prf != PKCS11Constants.CKM_SHA512_HMAC &&
                prf != PKCS11Constants.CKM_AES_CMAC) {
            String msg = "Expected Pseudo-Random Function to be SHA1-HMAC, ";
            msg += "SHA2-HMAC, or AES-CMAC, but got unknown PKCS#11 ";
            msg += "constant: " + prf;
            throw new IllegalArgumentException(msg);
        }

        if (params == null || params.length == 0) {
            String msg = "Expected non-null, non-zero length array of KDF ";
            msg += "parameters.";
            throw new IllegalArgumentException(msg);
        }

        int index = 0;
        for (KBKDFDataParameter param : params) {
            if (param instanceof KBKDFOptionalCounterParam) {
                KBKDFOptionalCounterParam kocp = (KBKDFOptionalCounterParam)param;
                if (kocp.widthInBits == -1) {
                    String msg = "Got unexpected data in KBKDF Optional ";
                    msg += "Counter Parameter at index " + index + ": ";
                    msg += "Expected valid counter specification, but got ";
                    msg += "widthInBits of -1. Call setCounterSpec(...) ";
                    msg += "before using this parameter.";
                    throw new IllegalArgumentException(msg);
                }
            }

            if (param instanceof KBKDFIterationVariableParam) {
                KBKDFIterationVariableParam kivp = (KBKDFIterationVariableParam)param;
                if (kivp.widthInBits != -1) {
                    String msg = "Got unexpected data in KBKDF Iteration ";
                    msg += "Variable Parameter at index " + index + ": ";
                    msg += "Expected empty counter specification, but got ";
                    msg += "widthInBits of " + kivp.widthInBits + ". Call ";
                    msg += "the no argument constructor instead to use this ";
                    msg += "parameter.";
                    throw new IllegalArgumentException(msg);
                }
            }

            if (param instanceof KBKDFDKMLengthParam) {
                KBKDFDKMLengthParam kdlp = (KBKDFDKMLengthParam)param;
                if (kdlp.widthInBits == 0) {
                    String msg = "Got unexpected data in KBKDF DKM Length ";
                    msg += "Parameter at index " + index + ": Expected valid ";
                    msg += "length specification, but got widthInBits of 0. ";
                    msg += "Call setLngthSpec(...) before using this ";
                    msg += "parameter.";
                    throw new IllegalArgumentException(msg);
                }
            }

            // Nothing to validate for byte array parameters.

            index += 1;
        }
    }

    protected native void acquireNativeResourcesInternal() throws Exception;
    protected native void releaseNativeResourcesInternal() throws Exception;
}
