package org.mozilla.jss.crypto;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import org.mozilla.jss.pkcs11.PKCS11Constants;
import org.mozilla.jss.util.NativeEnclosure;

/**
 * This class is utilized by JSS to implement OAEP support.
 *
 * Unlike the existing OAEPParameterSpec in the JCA, this class supports
 * NativeEnclosure, allowing it to be used within low-level JNI calls. We
 * support copying from an existing OAEPParameterSpec instance (so use is
 * interchangeable within JSS) and support setting members from JSS-specific
 * types.
 *
 * Note that this class cannot be used with other JCA providers natively.
 */
public class JSSOAEPParameterSpec extends NativeEnclosure implements AlgorithmParameterSpec {
    public long hashAlg;
    public long mgf;
    public byte[] sourceData;

    public JSSOAEPParameterSpec(String mdName, String mgfName, AlgorithmParameterSpec mgfSpec, PSource pSrc) {
        setDigestAlgorithm(mdName);
        setMaskGenAlgorithm(mgfName);
        setMaskGenAlgorithmType(mgfSpec);
        setPSource(pSrc);
    }

    public JSSOAEPParameterSpec(OAEPParameterSpec copy) {
        setDigestAlgorithm(copy.getDigestAlgorithm());
        setMaskGenAlgorithm(copy.getMGFAlgorithm());
        setMaskGenAlgorithmType(copy.getMGFParameters());
        setPSource(copy.getPSource());
    }

    public void setDigestAlgorithm(String algo) throws IllegalArgumentException {
        switch (algo.toLowerCase()) {
            case "md5":
            case "ckm_md5":
                hashAlg = PKCS11Constants.CKM_MD5;
                break;
            case "sha1":
            case "sha-1":
            case "ckm_sha_1":
                hashAlg = PKCS11Constants.CKM_SHA_1;
                break;
            case "sha256":
            case "sha-256":
            case "ckm_sha256":
                hashAlg = PKCS11Constants.CKM_SHA256;
                break;
            case "sha384":
            case "sha-384":
            case "ckm_sha384":
                hashAlg = PKCS11Constants.CKM_SHA384;
                break;
            case "sha512":
            case "sha-512":
            case "ckm_sha512":
                hashAlg = PKCS11Constants.CKM_SHA512;
                break;
            default:
                String msg = "Unknown algorithm identifier: " + algo;
                throw new IllegalArgumentException(msg);
        }
    }

    public void setDigestAlgorithm(DigestAlgorithm algo) throws IllegalArgumentException {
        if ((algo instanceof HMACAlgorithm) || (algo instanceof CMACAlgorithm)) {
            String msg = "Unable to use MAC digest algorithm " + algo;
            msg += " in place of an unkeyed hash algorithm";
            throw new IllegalArgumentException(msg);
        }

        hashAlg = algo.getEnum().getValue();
    }

    public void setDigestAlgorithm(long algo) throws IllegalArgumentException {
        hashAlg = algo;
    }

    public void setMaskGenAlgorithm(String algo) throws IllegalArgumentException {
        if (!algo.toLowerCase().equals("mgf1")) {
            String msg = "Unknown mask generation algorithm: " + algo;
            throw new IllegalArgumentException(msg);
        }

        // Do nothing. We just validate this data so if we get passed
        // something unexpected, we error out instead.
    }

    public void setMaskGenAlgorithmType(String algo) throws IllegalArgumentException {
        switch (algo.toLowerCase()) {
            case "sha1":
            case "sha-1":
            case "ckm_sha_1":
                hashAlg = PKCS11Constants.CKG_MGF1_SHA1;
                break;
            case "sha256":
            case "sha-256":
            case "ckm_sha256":
                hashAlg = PKCS11Constants.CKG_MGF1_SHA256;
                break;
            case "sha384":
            case "sha-384":
            case "ckm_sha384":
                hashAlg = PKCS11Constants.CKG_MGF1_SHA384;
                break;
            case "sha512":
            case "sha-512":
            case "ckm_sha512":
                hashAlg = PKCS11Constants.CKG_MGF1_SHA512;
                break;
            default:
                String msg = "Unknown mask generation algorithm identifier: " + algo;
                throw new IllegalArgumentException(msg);
        }
    }

    public void setMaskGenAlgorithmType(AlgorithmParameterSpec algo) throws IllegalArgumentException {
        if (!(algo instanceof MGF1ParameterSpec) || algo == null) {
            String msg = "Unknown mask generation algorithm parameter ";
            msg += "specification: " + algo;
            throw new IllegalArgumentException(msg);
        }

        MGF1ParameterSpec mgf1 = (MGF1ParameterSpec) algo;
        switch (mgf1.getDigestAlgorithm().toLowerCase()) {
            case "sha1":
            case "sha-1":
                mgf = PKCS11Constants.CKG_MGF1_SHA1;
                break;
            case "sha256":
            case "sha-256":
                mgf = PKCS11Constants.CKG_MGF1_SHA256;
                break;
            case "sha384":
            case "sha-384":
                mgf = PKCS11Constants.CKG_MGF1_SHA384;
                break;
            case "sha512":
            case "sha-512":
                mgf = PKCS11Constants.CKG_MGF1_SHA512;
                break;
            default:
                String msg = "Unknown mask generation algorithm identifier: ";
                msg += mgf1.getDigestAlgorithm();
                throw new IllegalArgumentException(msg);
        }
    }

    public void setMaskGenAlgorithmType(long algo) throws IllegalArgumentException {
        mgf = algo;
    }

    public void setPSource(PSource spec) throws IllegalArgumentException {
        if (spec == null) {
            sourceData = null;
            return;
        }

        if (!(spec instanceof PSource.PSpecified)) {
            String msg = "Expected PSource spec to be an instance of ";
            msg += "PSource.PSpecified, but wasn't: " + spec;
            throw new IllegalArgumentException(msg);
        }

        PSource.PSpecified value = (PSource.PSpecified) spec;
        setPSource(value.getValue());
    }

    public void setPSource(byte[] data) throws IllegalArgumentException {
        // PSource.PSpecified.DEFAULT is an allocated byte array of 0 length.
        // This confuses JSS_FromByteArray(...) into thinking that an error
        // occurred. Because PKCS#11 accepts a NULL pointer to go with a 0
        // length array, just set sourceData to NULL.
        if (data == null || data.length == 0) {
            sourceData = null;
            return;
        }

        sourceData = data;
    }

    protected native void acquireNativeResources() throws Exception;

    protected native void releaseNativeResources() throws Exception;
}
