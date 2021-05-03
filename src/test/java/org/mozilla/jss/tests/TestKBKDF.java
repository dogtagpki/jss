package org.mozilla.jss.tests;

import java.util.Arrays;
import java.util.Base64;

import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;

import org.mozilla.jss.*;
import org.mozilla.jss.crypto.*;
import org.mozilla.jss.pkcs11.*;
import org.mozilla.jss.pkcs11.attrs.*;
import org.mozilla.jss.util.*;

public class TestKBKDF {
    public static void main(String[] args) throws Exception {
        CryptoManager cm = CryptoManager.getInstance();
        TokenSupplier ts = TokenSupplierManager.getTokenSupplier();
        ts.setThreadToken(cm.getInternalCryptoToken());

        testCounterKDFNistCMAC();
        testFeedbackKDFNistCMAC();
        testPipelineKDFNistCMAC();
    }

    public static void testCounterKDFNistCMAC() throws Exception {
        javax.crypto.KeyGenerator kg = javax.crypto.KeyGenerator.getInstance("KbkdfCounterData", "Mozilla-JSS");

        SecretKeyFactory skf = SecretKeyFactory.getInstance("AES", "Mozilla-JSS");
        byte[] prf_key_bytes = Base64.getDecoder().decode("3/HlCsC2ncQPEFHUbCsGnA==");
        SecretKey prf_key = skf.generateSecret(new SecretKeySpec(prf_key_bytes, "AES"));
        SymmetricKey smkey = ((SecretKeyFacade)prf_key).key;

        CryptoToken token = smkey.getOwningToken();
        PK11Token tkn = (PK11Token)token;

        KBKDFCounterParams kcp = new KBKDFCounterParams();
        kcp.setPRF(PKCS11Algorithm.CKM_AES_CMAC);
        kcp.setPRFKey(prf_key);
        kcp.setKeySize(16);
        kcp.setDerivedKeyAlgorithm(PKCS11Algorithm.CKM_SHA_512_HMAC);

        kcp.addParameter(new KBKDFIterationVariableParam(true, 8));
        byte[] byte_array_param = Base64.getDecoder().decode("wW5uAsWj3MjXi5rBMGh3dhMQRVtOQUaZUdnmwiRaBksz/Yw7ASA6eCRIW/CmQGDEZItwfSYHk1aZMW6l");
        kcp.addParameter(new KBKDFByteArrayParam(byte_array_param));

        // RHEL 8.2 doesn't support additional derived keys.
        /*KBKDFDerivedKey kdk = new KBKDFDerivedKey();
        kdk.addAttribute(new CKAClass.Data());
        kdk.addAttribute(new CKAUsage.Encrypt());
        kdk.addAttribute(new CKAValueLen(16));
        kcp.addAdditionalDerivedKey(kdk);*/

        kg.init(kcp);

        SecretKey key = kg.generateKey();

        assert(key != null);

        byte[] encoded = key.getEncoded();
        byte[] expected = Base64.getDecoder().decode("i+jwhps8C6l7cYY9G594Ew==");

        assert(Arrays.equals(encoded, expected));

        /*SecretKey other_key = kdk.getKey(key, PKCS11Constants.CKM_SHA512_HMAC, true);
        byte[] other_encoded = other_key.getEncoded();
        byte[] other_expected = Base64.getDecoder().decode("DMdy/9fjofZGZMe3xhxlEg==");

        assert(Arrays.equals(encoded, expected));*/
    }

    public static void testFeedbackKDFNistCMAC() throws Exception {
        javax.crypto.KeyGenerator kg = javax.crypto.KeyGenerator.getInstance("KbkdfFeedbackData", "Mozilla-JSS");

        SecretKeyFactory skf = SecretKeyFactory.getInstance("AES", "Mozilla-JSS");
        byte[] prf_key_bytes = Base64.getDecoder().decode("ILu+NunIPFGETNMenCCUMQ==");
        SecretKey prf_key = skf.generateSecret(new SecretKeySpec(prf_key_bytes, "AES"));
        SymmetricKey smkey = ((SecretKeyFacade)prf_key).key;

        CryptoToken token = smkey.getOwningToken();
        PK11Token tkn = (PK11Token)token;

        KBKDFFeedbackParams kfp = new KBKDFFeedbackParams();
        kfp.setPRF(PKCS11Algorithm.CKM_AES_CMAC);
        kfp.setPRFKey(prf_key);
        kfp.setKeySize(64);
        kfp.setDerivedKeyAlgorithm(PKCS11Algorithm.CKM_SHA_512_HMAC);

        kfp.addParameter(new KBKDFOptionalCounterParam(true, 8));
        kfp.addParameter(new KBKDFIterationVariableParam());
        byte[] byte_array_param = Base64.getDecoder().decode("61B6/2n3fqtqugQgNKXLGZDXenzXKkmE8/skL7RM4PuUnpnZXYHlcQm31c03RqMhbEej");
        kfp.addParameter(new KBKDFByteArrayParam(byte_array_param));

        byte[] iv = Base64.getDecoder().decode("KPKKUyw744XXLsUyE2f4tg==");
        kfp.setInitialValue(iv);

        kg.init(kfp);

        SecretKey key = kg.generateKey();

        assert(key != null);

        byte[] encoded = key.getEncoded();
        byte[] expected = Base64.getDecoder().decode("J3pHPT9RSvP3YKI4M0PA63mfeanI8fMds34RBHhtO6IMn7KkLSmXzKt/eaXBnwlHBtMuCbzk93rtYWKvCNidHQ==");

        assert(Arrays.equals(encoded, expected));
    }

    public static void testPipelineKDFNistCMAC() throws Exception {
        javax.crypto.KeyGenerator kg = javax.crypto.KeyGenerator.getInstance("KbkdfPipelineData", "Mozilla-JSS");

        SecretKeyFactory skf = SecretKeyFactory.getInstance("AES", "Mozilla-JSS");
        byte[] prf_key_bytes = Base64.getDecoder().decode("xiVNld0QjpuyngBT3e7DUQ==");
        SecretKey prf_key = skf.generateSecret(new SecretKeySpec(prf_key_bytes, "AES"));
        SymmetricKey smkey = ((SecretKeyFacade)prf_key).key;

        CryptoToken token = smkey.getOwningToken();
        PK11Token tkn = (PK11Token)token;

        KBKDFPipelineParams kcp = new KBKDFPipelineParams();
        kcp.setPRF(PKCS11Algorithm.CKM_AES_CMAC);
        kcp.setPRFKey(prf_key);
        kcp.setKeySize(64);
        kcp.setDerivedKeyAlgorithm(PKCS11Algorithm.CKM_SHA_512_HMAC);

        kcp.addParameter(new KBKDFOptionalCounterParam(true, 8));
        kcp.addParameter(new KBKDFIterationVariableParam());
        byte[] byte_array_param = Base64.getDecoder().decode("IvSY/JuNS3IYi84wuph1/CsOs/52h02FQm5uWzsjfJ9EXy2iCmCrGJgC4sFSxKNgKqNC");
        kcp.addParameter(new KBKDFByteArrayParam(byte_array_param));

        kg.init(kcp);

        SecretKey key = kg.generateKey();

        assert(key != null);

        byte[] encoded = key.getEncoded();
        byte[] expected = Base64.getDecoder().decode("HhM6lS31WhHuA4EgN19h58AWKELIFxYGk7HzncC3lbxvNpHbd1zzr0sKn2n+y+mWef1LSHPdp0P1xqLS6HPybQ==");

        assert(Arrays.equals(encoded, expected));
    }
}
