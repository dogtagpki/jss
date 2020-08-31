package org.mozilla.jss.nss;

import java.lang.IllegalArgumentException;
import java.util.ArrayList;

import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.pkcs11.PK11Cert;
import org.mozilla.jss.ssl.SSLAlertEvent;
import org.mozilla.jss.util.GlobalRefProxy;

public class SSLFDProxy extends PRFDProxy {
    public PK11Cert clientCert;
    public GlobalRefProxy globalRef;

    public ArrayList<SSLAlertEvent> inboundAlerts;
    public int inboundOffset;

    public ArrayList<SSLAlertEvent> outboundAlerts;
    public int outboundOffset;

    public boolean needCertValidation;
    public boolean needBadCertValidation;
    public int badCertError;
    public boolean handshakeComplete;

    public CertAuthHandler certAuthHandler;
    public BadCertHandler badCertHandler;

    public SSLFDProxy(byte[] pointer) {
        super(pointer);

        globalRef = new GlobalRefProxy(this);
    }

    public void SetClientCert(X509Certificate cert) throws IllegalArgumentException {
        if (!(cert instanceof PK11Cert)) {
            throw new IllegalArgumentException("Unable to cast given certificate to PK11Cert: " + cert.getClass().getName());
        }

        clientCert = (PK11Cert)cert;
    }

    @Override
    protected synchronized void releaseNativeResources() throws Exception {
        synchronized (globalRef) {
            if (globalRef != null) {
                try {
                    globalRef.close();
                } finally {
                    globalRef = null;
                }
            }
        }
    }

    public int invokeCertAuthHandler() {
        return certAuthHandler.check(this);
    }

    public int invokeBadCertHandler(int error) {
        return badCertHandler.check(this, error);
    }
}
