package org.mozilla.jss.provider.javax.crypto;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.X509TrustManager;

/**
 * JSSNativeTrustManager is a JSSEngine TrustManager utilizing existing native
 * certificate checking functionality of NSS and JSS, compatible with the old
 * SSLSocket checks.
 *
 * Note: This class isn't compatible with external (non-JSS) SSLEngines.
 *
 * The only configuration possible is in CryptoManager's OCSP Policy, which
 * this obeys. No other configuration is possible. This is more performant
 * than other TrustManagers, because it saves a JNI call and handles the NSS
 * callback directly.
 */
public class JSSNativeTrustManager implements X509TrustManager {
    private String error_msg = getClass().getName() + " should not be used "
                             + "directly! Please use it with JSSEngine. Note "
                             + "that this TrustManager must be the only one "
                             + "passed to JSSEngine.";

    @Override
    public void checkClientTrusted(X509Certificate[] certChain, String authType) throws CertificateException {
        throw new RuntimeException(error_msg);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] certChain, String authType) throws CertificateException {
        throw new RuntimeException(error_msg);
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        throw new RuntimeException(error_msg);
    }
}
