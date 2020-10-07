package org.mozilla.jss.tests;

import java.util.Arrays;
import java.util.Base64;
import java.security.Key;

import javax.crypto.*;
import javax.crypto.spec.*;

import org.mozilla.jss.*;
import org.mozilla.jss.crypto.*;
import org.mozilla.jss.util.*;

public class TestCmac {
    private static final byte[] NIST_128 = Base64.getDecoder().decode("K34VFiiu0qar9xWICc9PPA==");
    private static final byte[] NIST_192 = Base64.getDecoder().decode("jnOw99oOZFLIEPMrgJB55WL46tJSLGt7");
    private static final byte[] NIST_256 = Base64.getDecoder().decode("YD3rEBXKcb4rc67whX13gR81LAc7YQjXLZgQowkU3/Q=");

    public static void main(String[] args) throws Exception {
        CryptoManager cm = CryptoManager.getInstance();
        CryptoToken tok = cm.getInternalKeyStorageToken();
        PasswordCallback cb = new FilePasswordCallback(args[1]);
        tok.login(cb);

        testNISTExamples();
    }

    /*
     * The following test vectors come from NIST's Examples with Intermediate
     * Values page:
     * https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
     *
     * These are the same vectors utilized by NSS in:
     * gtests/freebl_gtest/cmac_unittests.cc
     *
     * These same vectors are also found in FRC 4493, Section 4.
     */
    public static void testNISTExamples() throws Exception {
        byte[] all_input = Base64.getDecoder().decode("a8G+4i5An5bpPX4Rc5MXKq4tilceA6ycnrdvrEWvjlEwyBxGo1zkEeX7wRkaClLv9p8kRd9PmxetK0F75mw3EA==");
        int[] input_lengths = new int[] { 0, 16, 20, 64};

        byte[][] all_expected = new byte[][] {
            Base64.getDecoder().decode("ux1pKelZNyh/o30Sm3VnRg=="),
            Base64.getDecoder().decode("BwoWtGtNQUT3m92d0EoofA=="),
            Base64.getDecoder().decode("fYVEnqbqGcgjp794g3363g=="),
            Base64.getDecoder().decode("UfC+v347nZL8SXQXeTY8/g=="),
            Base64.getDecoder().decode("0X3fRq2qzeUxysSD3nqTZw=="),
            Base64.getDecoder().decode("npmnvzHnEJAGYvZeYXxRhA=="),
            Base64.getDecoder().decode("PXXBlO2WBwREqfp+x0Ds+A=="),
            Base64.getDecoder().decode("odXfDu15D3lNd1iWWfOaEQ=="),
            Base64.getDecoder().decode("Aoli9ht7+J78a1UfRmfZgw=="),
            Base64.getDecoder().decode("KKcCP0Uuj4K9S/KNjDfDXA=="),
            Base64.getDecoder().decode("FWcn3Ah4lEoCPB/gO61tkw=="),
            Base64.getDecoder().decode("4ZkhkFSfbtVpaiwFbDFUEA==")
        };

        for (int i = 0; i < all_expected.length; i++) {
            byte[] key = getKey(i);
            byte[] input = Arrays.copyOf(all_input, input_lengths[i % input_lengths.length]);
            byte[] expected = all_expected[i];

            testCMAC(key, input, expected);
        }
    }

    public static byte[] getKey(int index) {
        if (index < 4) {
            return NIST_128;
        } else if (index < 8) {
            return NIST_192;
        } else if (index < 12) {
            return NIST_256;
        }

        return null;
    }

    public static void testCMAC(byte[] key_bytes, byte[] input, byte[] expected) throws Exception {
        Mac mac = Mac.getInstance("AES_CMAC", "Mozilla-JSS");
        SecretKeyFactory factory = SecretKeyFactory.getInstance("AES", "Mozilla-JSS");
        Key key = factory.generateSecret(new SecretKeySpec(key_bytes, "AES"));
        mac.init(key);

        byte[] actual = mac.doFinal(input);

        assert(Arrays.equals(actual, expected));
    }
}
