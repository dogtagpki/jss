package org.mozilla.jss.tests;

import org.mozilla.jss.nss.PR;
import org.mozilla.jss.nss.PRFDProxy;
import org.mozilla.jss.nss.SSL;
import org.mozilla.jss.nss.SecurityStatusResult;

public class TestRawSSL {
    public static void TestSSLImportFD() {
        PRFDProxy fd = PR.NewTCPSocket();
        assert(fd != null);

        PRFDProxy ssl_fd = SSL.ImportFD(null, fd);
        assert(ssl_fd != null);

        assert(PR.Close(ssl_fd) == 0);
    }

    public static void TestSSLOptions() throws Exception {
        PRFDProxy fd = PR.NewTCPSocket();
        assert(fd != null);

        PRFDProxy ssl_fd = SSL.ImportFD(null, fd);
        assert(ssl_fd != null);

        // 8 == SSL_ENABLE_SSL3; disable it
        assert(SSL.OptionSet(ssl_fd, 8, 0) == 0);

        // Validate that the set worked.
        assert(SSL.OptionGet(ssl_fd, 8) == 0);

        // Renable SSL_ENABLE_SSL3 and validate it worked
        assert(SSL.OptionSet(ssl_fd, 8, 1) == 0);
        assert(SSL.OptionGet(ssl_fd, 8) == 1);

        // Ensure that setting an invalid option fails
        assert(SSL.OptionSet(ssl_fd, 799999, 0) != 0);

        // Ensure that getting an invalid option fails
        try {
            SSL.OptionGet(ssl_fd, 79999999);
            assert(false);
        } catch (Exception e) {
            assert(true);
        }

        assert(PR.Close(ssl_fd) == 0);
    }

    public static void TestSSLSetURL() {
        PRFDProxy fd = PR.NewTCPSocket();
        assert(fd != null);

        assert(SSL.SetURL(fd, "https://google.com") != 0);

        PRFDProxy ssl_fd = SSL.ImportFD(null, fd);
        assert(ssl_fd != null);

        assert(SSL.SetURL(ssl_fd, "https://google.com") == 0);

        assert(PR.Close(ssl_fd) == 0);
    }

    public static void TestSSLSecurityStatus() {
        PRFDProxy fd = PR.NewTCPSocket();
        assert(fd != null);

        assert(SSL.SecurityStatus(fd) == null);

        PRFDProxy ssl_fd = SSL.ImportFD(null, fd);
        assert(ssl_fd != null);

        SecurityStatusResult r = SSL.SecurityStatus(ssl_fd);
        assert(r.on == 0);

        assert(PR.Close(ssl_fd) == 0);
    }

    public static void TestSSLResetHandshake() {
        PRFDProxy fd = PR.NewTCPSocket();
        assert(fd != null);

        assert(SSL.ResetHandshake(fd, false) != 0);

        PRFDProxy ssl_fd = SSL.ImportFD(null, fd);
        assert(SSL.ResetHandshake(fd, false) == 0);

        assert(PR.Close(ssl_fd) == 0);
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

        System.out.println("Calling TestSSLSecurityStatus()...");
        TestSSLSecurityStatus();

        System.out.println("Calling TestSSLResetHandshake()...");
        TestSSLResetHandshake();
    }
}
