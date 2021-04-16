package org.mozilla.jss.tests;

import java.io.*;
import java.security.KeyPair;

import org.mozilla.jss.*;
import org.mozilla.jss.asn1.*;
import org.mozilla.jss.crypto.*;
import org.mozilla.jss.pkcs10.*;
import org.mozilla.jss.pkix.primitive.*;

public class TestCertificationRequest {
    public static void main(String[] argv) throws Exception {
        if (argv.length > 2 || argv.length < 1) {
            System.out.println("Usage: TestCertificationRequest <dbdir> [<certfile>]");
            System.exit(0);
        }

        CryptoManager cm = CryptoManager.getInstance();

        CertificationRequest cert;

        // read in a cert
        FileInputStream fis = new FileInputStream(argv[1]);
        try (BufferedInputStream bis = new BufferedInputStream(fis)) {
            cert = (CertificationRequest) CertificationRequest.getTemplate().decode(bis);
        }

        CertificationRequestInfo info = cert.getInfo();

        info.print(System.out);
    }
}
