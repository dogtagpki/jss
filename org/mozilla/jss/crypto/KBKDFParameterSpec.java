package org.mozilla.jss.crypto;

import java.security.InvalidKeyException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

import java.util.Arrays;
import java.util.ArrayList;

import org.mozilla.jss.pkcs11.PK11SymKey;
import org.mozilla.jss.util.NativeEnclosure;

public abstract class KBKDFParameterSpec extends NativeEnclosure implements AlgorithmParameterSpec, KeySpec {
    /* Need access from outside; no real protections in setters outside
     * of additional input types. */
    public PK11SymKey prfKey;
    public long derivedKeyAlgorithm;
    public int keySize;

    protected long prf;
    protected KBKDFDataParameter[] params;
    protected KBKDFDerivedKey[] additional_keys;

    /**
     * Set the underlying pseudo-random function from a PKCS11Algorithm enum
     * value.
     */
    public void setPRF(PKCS11Algorithm prf) throws IllegalArgumentException {
        this.prf = prf.getValue();
    }

    /**
     * Set the underlying pseudo-random function from a DigestAlgorithm
     * (HMACAlgorithm or CMACAlgorithm) instance.
     */
    public void setPRF(DigestAlgorithm prf) throws IllegalArgumentException {
        if (!(prf instanceof HMACAlgorithm) && !(prf instanceof CMACAlgorithm)) {
            String msg = "Unknown pseudo-random function type: expected ";
            msg += "either HMAC or CMAC algorithms. Got: ";
            msg += prf.getClass().getName();
            throw new IllegalArgumentException(msg);
        }

        this.prf = prf.getEnum().getValue();
    }

    /**
     * Set the underlying pseudo-random function from a PKCS#11 constant;
     * see org.mozilla.jss.pkcs11.PKCS11Constants for permitted values.
     */
    public void setPRF(long prf) {
        this.prf = prf;
    }

    /**
     * Set the base key used with the underlying PRF.
     *
     * Must be importable to a JSS SymmetricKey or SecretKeyFacade.
     */
    public void setPRFKey(SecretKey key) throws InvalidKeyException {
        if (key instanceof PK11SymKey) {
            prfKey = (PK11SymKey)key;
            return;
        }

        if (key instanceof SecretKeyFacade) {
            setPRFKey(((SecretKeyFacade)key).key);
            return;
        }

        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance(key.getAlgorithm(), "Mozilla-JSS");
            SecretKey translated = skf.translateKey(key);
            if (translated instanceof SymmetricKey) {
                setPRFKey(translated);
                return;
            }

            if (translated instanceof SecretKeyFacade) {
                setPRFKey(((SecretKeyFacade)translated).key);
                return;
            }

            String msg = "Expected key to become an instance of ";
            msg += "org.mozilla.jss.crypto.SymmetricKey or ";
            msg += "org.mozilla.jss.crypto.SecretKeyFacade after ";
            msg += "translation, but got: ";
            msg += translated.getClass().getName();

            throw new InvalidKeyException(msg);
        } catch (Exception excep) {
            throw new InvalidKeyException("Unable to import key: " + excep.getMessage(), excep);
        }
    }

    /**
     * Set the algorithm for the derived key from a PKCS11Algorithm enum value.
     */
    public void setDerivedKeyAlgorithm(PKCS11Algorithm algo) throws IllegalArgumentException {
        if (algo == null) {
            String msg = "Expected non-null PKCS11Algorithm value, but was null.";
            throw new IllegalArgumentException(msg);
        }

        derivedKeyAlgorithm = algo.getValue();
    }

    /**
     * Sets the algorithm for the derived key from a PKCS#11 value; see
     * org.mozilla.jss.pkcs11.PKCS11Constants for constant values.
     */
    public void setDerivedKeyAlgorithm(long algo) throws IllegalArgumentException {
        derivedKeyAlgorithm = algo;
    }

    /**
     * Set the size of the derived key.
     *
     * If zero, will attempt to use the derived key algorithm's default key
     * size.
     */
    public void setKeySize(int keySize) {
        this.keySize = keySize;
    }

    /**
     * Set parameters for key derivation.
     *
     * This overwrites all existing parameters. Note that params cannot be
     * NULL.
     */
    public void setParameters(KBKDFDataParameter[] params) throws IllegalArgumentException {
        if (params == null) {
            String msg = "Expected populated array of KBKDFDataParameters, ";
            msg += "but was null.";
            throw new IllegalArgumentException(msg);
        }

        this.params = params;
    }

    /**
     * Appends (to the end) a new data parameter.
     */
    public void addParameter(KBKDFDataParameter param) throws IllegalArgumentException {
        if (param == null) {
            String msg = "Expected non-null instance of KBKDFDataParameters, ";
            msg += "but was null.";
            throw new IllegalArgumentException(msg);
        }

        ArrayList<KBKDFDataParameter> data_params;
        if (this.params == null) {
            data_params = new ArrayList<KBKDFDataParameter>(1);
        } else {
            data_params = new ArrayList<KBKDFDataParameter>(Arrays.asList(this.params));
        }
        data_params.add(param);

        this.params = data_params.toArray(new KBKDFDataParameter[data_params.size()]);
    }

    /**
     * Set an array of additional derived keys.
     */
    public void setAdditionalDerivedKeys(KBKDFDerivedKey[] additional_keys) throws IllegalArgumentException {
        if (additional_keys == null) {
            String msg = "Expected populated array of KBKDFDerivedKey, ";
            msg += "but was null.";
            throw new IllegalArgumentException(msg);
        }

        this.additional_keys = additional_keys;
    }

    /**
     * Append (to the end) a new derived key.
     */
    public void addAdditionalDerivedKey(KBKDFDerivedKey derived_key) throws IllegalArgumentException {
        if (derived_key == null) {
            String msg = "Expected non-null instance of KBKDFDerivedKey, ";
            msg += "but was null.";
            throw new IllegalArgumentException(msg);
        }

        ArrayList<KBKDFDerivedKey> keys;
        if (additional_keys == null) {
           keys = new ArrayList<KBKDFDerivedKey>(1);
        } else {
           keys = new ArrayList<KBKDFDerivedKey>(Arrays.asList(additional_keys));
        }
        keys.add(derived_key);

        additional_keys = keys.toArray(new KBKDFDerivedKey[keys.size()]);
    }

    protected void acquireNativeResources() throws Exception {
        validateParameters();

        if (params != null) {
            for (KBKDFDataParameter param : params) {
                param.open();
            }
        }

        if (additional_keys != null) {
            for (KBKDFDerivedKey key : additional_keys) {
                key.open();
            }
        }

        acquireNativeResourcesInternal();
    }

    protected void releaseNativeResources() throws Exception {
        if (additional_keys != null) {
            for (KBKDFDerivedKey key : additional_keys) {
                key.close();
            }
        }

        if (params != null) {
            for (KBKDFDataParameter param : params) {
                param.close();
            }
        }

        releaseNativeResourcesInternal();
    }

    protected abstract void acquireNativeResourcesInternal() throws Exception;
    protected abstract void releaseNativeResourcesInternal() throws Exception;

    /**
     * Validate all class members prior to acquiring native resources.
     *
     * This is implemented by the derived KBKDF modes in an effort to give
     * useful exceptions before derivation, instead of vague errors during
     * derivation.
     */
    protected abstract void validateParameters() throws IllegalArgumentException;
}
