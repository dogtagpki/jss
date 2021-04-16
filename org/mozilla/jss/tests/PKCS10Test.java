package org.mozilla.jss.tests;

import java.security.PublicKey;
import java.security.KeyPair;
import java.security.interfaces.*;

import org.mozilla.jss.*;
import org.mozilla.jss.crypto.*;
import org.mozilla.jss.netscape.security.pkcs.*;
import org.mozilla.jss.netscape.security.x509.*;

public class PKCS10Test {
    public static void main(String[] args) throws Exception {
        CryptoManager cm = CryptoManager.getInstance();

        CertAndKeyGen ckg = new CertAndKeyGen("RSA", "SHA256withRSA");
        ckg.generate(4096);
        PKCS10 csr = ckg.getCertRequest(new X500Name("CN=localhost"));
    }
}
