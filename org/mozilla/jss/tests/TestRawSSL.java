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

    public static void TestSSLOptionSet() {
        PRFDProxy fd = PR.NewTCPSocket();
        assert(fd != null);

        PRFDProxy ssl_fd = SSL.ImportFD(null, fd);
        assert(ssl_fd != null);

        // 7 == SSL_ENABLE_SSL2; disable it
        assert(SSL.OptionSet(ssl_fd, 7, 0) == 0);

        // Ensure that setting an invalid option fails
        assert(SSL.OptionSet(ssl_fd, 799999, 0) != 0);

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

    public static void main(String[] args) {
        System.loadLibrary("jss4");

        if (args.length != 1) {
            System.out.println("Usage: TestRawSSL /path/to/nssdb");
            System.exit(1);
        }

        System.out.println("Calling TestSSLImportFD()...");
        TestSSLImportFD();

        System.out.println("Calling TestSSLOptionSet()...");
        TestSSLOptionSet();

        System.out.println("Calling TestSSLSetURL()...");
        TestSSLSetURL();

        System.out.println("Calling TestSSLSecurityStatus()...");
        TestSSLSecurityStatus();

        System.out.println("Calling TestSSLResetHandshake()...");
        TestSSLResetHandshake();
    }
}
