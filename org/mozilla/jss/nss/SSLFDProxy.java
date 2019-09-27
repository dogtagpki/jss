package org.mozilla.jss.nss;

import java.lang.IllegalArgumentException;

import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.pkcs11.PK11Cert;

public class SSLFDProxy extends PRFDProxy {
    public PK11Cert clientCert;

    public SSLFDProxy(byte[] pointer) {
        super(pointer);
    }

    public void SetClientCert(X509Certificate cert) throws IllegalArgumentException {
        if (!(cert instanceof PK11Cert)) {
            throw new IllegalArgumentException("Unable to cast given certificate to PK11Cert: " + cert.getClass().getName());
        }

        clientCert = (PK11Cert)cert;
    }

    protected native void releaseNativeResources();

    protected void finalize() throws Throwable {
        super.finalize();
    }
}
