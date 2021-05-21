package org.mozilla.jss.crypto;

import org.mozilla.jss.pkcs11.PKCS11Constants;

public class KBKDFCounterParams extends KBKDFParameterSpec {
    public KBKDFCounterParams() {
    }

    @Override
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
                String msg = "Got unexpected data parameter at index " + index;
                msg += ": KBKDF Optional Counter Parameter is forbidden from ";
                msg += "use with Counter mode KBKDF.";
                throw new IllegalArgumentException(msg);
            }

            if (param instanceof KBKDFIterationVariableParam) {
                KBKDFIterationVariableParam kivp = (KBKDFIterationVariableParam) param;
                if (kivp.widthInBits == -1) {
                    String msg = "Got unexpected data in KBKDF Iteration ";
                    msg += "Variable Parameter at index " + index + ": ";
                    msg += "Expected valid counter specification, but got ";
                    msg += "widthInBits of -1. Call setCounterSpec(...) ";
                    msg += "before using this parameter.";
                    throw new IllegalArgumentException(msg);
                }
            }

            if (param instanceof KBKDFDKMLengthParam) {
                KBKDFDKMLengthParam kdlp = (KBKDFDKMLengthParam) param;
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

    @Override
    protected native void acquireNativeResourcesInternal() throws Exception;

    @Override
    protected native void releaseNativeResourcesInternal() throws Exception;
}
