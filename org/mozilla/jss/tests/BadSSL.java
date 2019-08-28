package org.mozilla.jss.tests;

import org.mozilla.jss.CryptoManager;

import org.mozilla.jss.ssl.SSLSocket;
import org.mozilla.jss.ssl.SSLSocketException;

import org.mozilla.jss.util.NativeErrcodes;

/**
 * The BadSSL test case maintains an internal mapping from badssl.com
 * subdomains to expected exceptions and validates they occur.
 *
 * Since badssl.com offers no guaranteed SLA or availability, we likely
 * shouldn't add this site to automated tests.
 */

public class BadSSL {
    public static void main(String[] args) throws Exception {
        boolean ocsp = false;

        if (args.length < 1) {
            System.out.println("Usage: BadSSL nssdb [LEAF_AND_CHAIN]");
            return;
        }

        if (args.length >= 2 && args[1].equals("LEAF_AND_CHAIN")) {
            System.out.println("Enabling leaf and chain policy...");
            ocsp = true;
        }

        CryptoManager.initialize(args[0]);
        CryptoManager cm = CryptoManager.getInstance();

        if (ocsp) {
            cm.setOCSPPolicy(CryptoManager.OCSPPolicy.LEAF_AND_CHAIN);
        }


        // Test cases which should fail due to various certificate errors.
        testExpired();
        testWrongHost();
        testSelfSigned();
        testUntrustedRoot();

        // The following test cases depend on crypto-policies or local NSS
        // configuration.
        testSHA1();
        testRC4MD5();
        testRC4();
        test3DES();
        testNULL();

        // The following test cases depend on OCSP being enabled.
        if (ocsp) {
            testRevoked();
        }

        // Test cases which should pass given the correct root certs.
        testSHA256();
        testSHA384();
        testSHA512();

        testECC256();
        testECC384();

        testRSA2048();
        testRSA4096();
        testRSA8192();

        testExtendedValidation();
    }

    /* Test cases whose handshakes should fail below. */

    public static void testExpired() throws Exception {
        testHelper("expired.badssl.com", 443, new String[]{ "(-8181)", "has expired" });
    }

    public static void testWrongHost() throws Exception {
        testHelper("wrong.host.badssl.com", 443, new String[]{ "(-12276)", "domain name does not match" });
    }

    public static void testSelfSigned() throws Exception {
        testHelper("self-signed.badssl.com", 443, new String[]{ "(-8101)", "(-8156)", "type not approved", "issuer certificate is invalid" });
    }

    public static void testUntrustedRoot() throws Exception {
        testHelper("untrusted-root.badssl.com", 443, new String[]{ "(-8172)", "certificate issuer has been marked as not trusted" });
    }

    public static void testRevoked() throws Exception {
        testHelper("revoked.badssl.com", 443, new String[]{ "(-8180)", "has been revoked" });
    }

    public static void testSHA1() throws Exception {
        try {
            testHelper("sha1-intermediate.badssl.com", 443, new String[] { "(-12286)", "Cannot communicate securely" });
        } catch (Exception e) { }
    }

    public static void testRC4MD5() throws Exception {
        try {
            testHelper("rc4-md5.badssl.com", 443, new String[] { "(-12286)", "Cannot communicate securely" });
        } catch (Exception e) { }
    }

    public static void testRC4() throws Exception {
        try {
            testHelper("rc4.badssl.com", 443, new String[] { "(-12286)", "Cannot communicate securely" });
        } catch (Exception e) { }
    }

    public static void test3DES() throws Exception {
        try {
            testHelper("3des.badssl.com", 443, new String[] { "(-12286)", "Cannot communicate securely" });
        } catch (Exception e) { }
    }

    public static void testNULL() throws Exception {
        try {
            testHelper("null.badssl.com", 443, new String[] { "(-12286)", "Cannot communicate securely" });
        } catch (Exception e) { }
    }

    /* Test cases which should handshake successfully below. */

    public static void testSHA256() throws Exception {
        testHelper("sha256.badssl.com", 443);
    }

    public static void testSHA384() throws Exception {
        testHelper("sha384.badssl.com", 443);
    }

    public static void testSHA512() throws Exception {
        testHelper("sha512.badssl.com", 443);
    }

    public static void testECC256() throws Exception {
        testHelper("ecc256.badssl.com", 443);
    }

    public static void testECC384() throws Exception {
        testHelper("ecc384.badssl.com", 443);
    }

    public static void testRSA2048() throws Exception {
        testHelper("rsa2048.badssl.com", 443);
    }

    public static void testRSA4096() throws Exception {
        testHelper("rsa4096.badssl.com", 443);
    }

    public static void testRSA8192() throws Exception {
        testHelper("rsa8192.badssl.com", 443);
    }

    public static void testExtendedValidation() throws Exception {
        testHelper("extended-validation.badssl.com", 443);
    }

    /* Test case helpers. */

    public static void testHelper(String host, int port) throws Exception {
        testSite(host, port);
        System.out.println("\t...ok");
    }

    public static void testHelper(String host, int port, String[] substrs) throws Exception {
        try {
            testSite(host, port);
        } catch (SSLSocketException sse) {
            String actual = sse.getMessage().toLowerCase();

            for (String expected : substrs) {
                if (actual.contains(expected.toLowerCase())) {
                    System.out.println("\t...got expected error message.");
                    return;
                }
            }

            System.err.println("\tUnexpected error message: " + actual);
            throw sse;
        }

        throw new RuntimeException("Expected to get an exception, but didn't!");
    }

    public static void testHelper(String host, int port, int[] codes) throws Exception {
        try {
            testSite(host, port);
        } catch (SSLSocketException sse) {
            int actual = sse.getErrcode();
            for (int expected : codes) {
                if (actual == expected) {
                    System.out.println("\t...got expected error code.");
                    return;
                }
            }

            System.err.println("\tUnexpected error code: " + actual);
            throw sse;
        }

        throw new RuntimeException("Expected to get an exception, but didn't!");
    }

    public static void testSite(String host, int port) throws Exception {
        System.out.println("Testing connection to " + host + ":" + port);
        SSLSocket sock = new SSLSocket(host, 443);
        sock.forceHandshake();
        sock.shutdownOutput();
        sock.shutdownInput();
        sock.close();
    }
}
