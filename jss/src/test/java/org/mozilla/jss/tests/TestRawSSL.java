package org.mozilla.jss.tests;

import org.mozilla.jss.nss.PR;
import org.mozilla.jss.nss.PRFDProxy;
import org.mozilla.jss.nss.SSLFDProxy;
import org.mozilla.jss.nss.SSL;
import org.mozilla.jss.nss.SecurityStatusResult;
import org.mozilla.jss.nss.SSLChannelInfo;
import org.mozilla.jss.nss.SSLPreliminaryChannelInfo;

import org.mozilla.jss.ssl.SSLCipher;

public class TestRawSSL {
    public static void TestSSLImportFD() throws Exception {
        PRFDProxy fd = PR.NewTCPSocket();
        assert(fd != null);

        SSLFDProxy ssl_fd = SSL.ImportFD(null, fd);
        assert(ssl_fd != null);

        assert(PR.Close(ssl_fd) == PR.SUCCESS);
    }

    public static void TestSSLOptions() throws Exception {
        PRFDProxy fd = PR.NewTCPSocket();
        assert(fd != null);

        SSLFDProxy ssl_fd = SSL.ImportFD(null, fd);
        assert(ssl_fd != null);

        // 8 == SSL_ENABLE_SSL3; disable it
        assert(SSL.OptionSet(ssl_fd, 8, 0) == SSL.SECSuccess);

        // Validate that the set worked.
        assert(SSL.OptionGet(ssl_fd, 8) == SSL.SECSuccess);

        // Renable SSL_ENABLE_SSL3 and validate it worked
        assert(SSL.OptionSet(ssl_fd, 8, 1) == SSL.SECSuccess);
        assert(SSL.OptionGet(ssl_fd, 8) == 1);

        // Ensure that setting an invalid option fails
        assert(SSL.OptionSet(ssl_fd, 799999, 0) != SSL.SECSuccess);

        // Ensure that getting an invalid option fails
        try {
            SSL.OptionGet(ssl_fd, 79999999);
            assert(false);
        } catch (Exception e) {
            assert(true);
        }

        assert(PR.Close(ssl_fd) == PR.SUCCESS);
    }

    public static void TestSSLCipherPref() throws Exception {
        PRFDProxy fd = PR.NewTCPSocket();
        assert(fd != null);

        SSLFDProxy ssl_fd = SSL.ImportFD(null, fd);
        assert(ssl_fd != null);

        int cipher = SSLCipher.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.getID();

        // Ensure that setting a ciphersuite works correctly
        assert(SSL.CipherPrefSet(ssl_fd, cipher, false) == SSL.SECSuccess);
        assert(SSL.CipherPrefGet(ssl_fd, cipher) == false);

        assert(SSL.CipherPrefSet(ssl_fd, cipher, true) == SSL.SECSuccess);
        assert(SSL.CipherPrefGet(ssl_fd, cipher) == true);

        // Ensure that using an invalid ciphersuite fails.
        assert(SSL.CipherPrefSet(ssl_fd, 0x999999, false) == SSL.SECFailure);
        try {
            SSL.CipherPrefGet(ssl_fd, 0x999999);
            assert(false);
        } catch (Exception e) {
            assert(true);
        }

        assert(PR.Close(ssl_fd) == PR.SUCCESS);
    }

    public static void TestSSLSetURL() throws Exception {
        PRFDProxy fd = PR.NewTCPSocket();
        assert(fd != null);

        SSLFDProxy ssl_fd = SSL.ImportFD(null, fd);
        assert(ssl_fd != null);

        assert(SSL.SetURL(ssl_fd, "https://google.com") == SSL.SECSuccess);

        assert(PR.Close(ssl_fd) == PR.SUCCESS);
    }

    public static void TestSSLSecurityStatus() throws Exception {
        PRFDProxy fd = PR.NewTCPSocket();
        assert(fd != null);

        SSLFDProxy ssl_fd = SSL.ImportFD(null, fd);
        assert(ssl_fd != null);

        SecurityStatusResult r = SSL.SecurityStatus(ssl_fd);
        assert(r != null);
        assert(r.on == 0);

        // Validate toString works
        System.out.println(r.toString());

        assert(PR.Close(ssl_fd) == PR.SUCCESS);
    }

    public static void TestSSLGetChannelInfo() throws Exception {
        PRFDProxy fd = PR.NewTCPSocket();
        assert(fd != null);

        SSLFDProxy ssl_fd = SSL.ImportFD(null, fd);
        assert(ssl_fd != null);

        SSLChannelInfo r = SSL.GetChannelInfo(ssl_fd);
        assert(r != null);
        assert(r.getProtocolVersion() == null);

        System.out.println(r.toString());

        assert(PR.Close(ssl_fd) == PR.SUCCESS);
    }

    public static void TestSSLGetPreliminaryChannelInfo() throws Exception {
        PRFDProxy fd = PR.NewTCPSocket();
        assert(fd != null);

        SSLFDProxy ssl_fd = SSL.ImportFD(null, fd);
        assert(ssl_fd != null);

        SSLPreliminaryChannelInfo r = SSL.GetPreliminaryChannelInfo(ssl_fd);
        assert(r != null);
        assert(r.haveProtocolVersion() == false);
        assert(r.haveCipherSuite() == false);
        assert(r.haveZeroRttCipherSuite() == false);
        assert(r.havePeerAuth() == false);

        System.out.println(r.toString());

        assert(PR.Close(ssl_fd) == PR.SUCCESS);
    }

    public static void TestSSLResetHandshake() throws Exception {
        PRFDProxy fd = PR.NewTCPSocket();
        assert(fd != null);

        SSLFDProxy ssl_fd = SSL.ImportFD(null, fd);
        assert(SSL.ResetHandshake(ssl_fd, false) == SSL.SECSuccess);

        assert(PR.Close(ssl_fd) == PR.SUCCESS);
    }

    public static void main(String[] args) throws Exception {
        System.loadLibrary("jss4");

        if (args.length != 1) {
            System.out.println("Usage: TestRawSSL /path/to/nssdb");
            System.exit(1);
        }

        System.out.println("Calling TestSSLImportFD()...");
        TestSSLImportFD();

        System.out.println("Calling TestSSLOptions()...");
        TestSSLOptions();

        System.out.println("Calling TestSSLSetURL()...");
        TestSSLSetURL();

        System.out.println("Calling TestSSLCipherPref()...");
        TestSSLCipherPref();

        System.out.println("Calling TestSSLSecurityStatus()...");
        TestSSLSecurityStatus();

        System.out.println("Calling TestSSLGetChannelInfo()...");
        TestSSLGetChannelInfo();

        System.out.println("Calling TestSSLGetPreliminaryChannelInfo()...");
        TestSSLGetPreliminaryChannelInfo();

        System.out.println("Calling TestSSLResetHandshake()...");
        TestSSLResetHandshake();
    }
}
