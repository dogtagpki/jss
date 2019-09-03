package org.mozilla.jss.provider.javax.crypto;

import java.security.cert.CertificateException;

import javax.net.ssl.X509TrustManager;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.CertificateUsage;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.netscape.security.util.Cert;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/* In the below, X509Certificate refers to org.mozilla.jss.crypto.X509Certificate,
 * which implements the java.security.cert.X509Certificate interface. However,
 * the latter is required as an input parameter to the overridden methods. */

public class JSSOCSPTrustManager implements X509TrustManager {
    final static Logger logger = LoggerFactory.getLogger(JSSTrustManager.class);

    public static CryptoManager cm;

    public void initCryptoManager() throws Exception {
        if (cm == null) {
            // Technically this could throw a NotInitializedException. However
            // in most cases, creating the JSSProvider requires creating the
            // CryptoManager, so such an exception is an indication of an
            // unsupported usage of the JSSProvider interface.
            cm = CryptoManager.getInstance();
        }
    }

    public X509Certificate[] downcastChain(java.security.cert.X509Certificate[] chain, boolean isClient) throws Exception {
        // Create NSS-backed certificates via importDERCert.
        int cert_index = 0;
        X509Certificate[] jssChain = new X509Certificate[chain.length - 1];
        for (cert_index = 0; cert_index < chain.length - 1; cert_index++) {
            if (chain[cert_index] instanceof X509Certificate) {
                // We already have a working NSS-backed certificate, so no
                // need to convert it.
                jssChain[cert_index] = (X509Certificate) chain[cert_index];
            } else {
                // These all are SSL (Intermediate) CA certificates. We don't
                // want to store them permanently or give them a nickname.
                byte[] der = chain[cert_index].getEncoded();
                jssChain[cert_index] = cm.importDERCert(der, CertificateUsage.SSLCA, false, null);
            }
        }

        if (chain[cert_index] instanceof X509Certificate) {
            jssChain[cert_index] = (X509Certificate) chain[cert_index];
        } else {
            // These all are SSL (Intermediate) CA certificates. We don't
            // want to store them permanently or give them a nickname.
            byte[] der = chain[cert_index].getEncoded();
            CertificateUsage usage = CertificateUsage.SSLServer;
            if (isClient) {
                usage = CertificateUsage.SSLClient;
            }
            jssChain[cert_index] = cm.importDERCert(der, usage, false, null);
        }

        return jssChain;
    }

    public void checkTrusted(java.security.cert.X509Certificate[] chain, boolean isClient) throws Exception {
        // Make sure we have a useful reference to the CryptoManager.
        initCryptoManager();

        // Sort the chain from root -> leaf. This enforces that the very last
        // certificate is the one we care most about validating (with the
        // others being stepping stones on the way). Additionally, this
        // guarantees that all other certificates in the chain should be CA
        // certificates and the last one either being a SSLClient or a SSLServer
        // certificate, depending on the value of isClient.
        chain = Cert.sortCertificateChain(chain);

        // Get references to CERTCertificate for the sorted chain.
        X509Certificate[] jssChain = downcastChain(chain, isClient);
    }

    @Override
    public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) throws CertificateException {
        try {
            checkTrusted(chain, true);
        } catch (CertificateException e) {
            logger.warn("JSSOCSPTrustManager: Invalid SSL server certificate: " + e);
            throw e;
        } catch (Exception e) {
            logger.warn("JSSOCSPTrustManager: Unable to validate SSL server certificate: " + e);
            throw new CertificateException(e);
        }
    }

    @Override
    public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) throws CertificateException {
        try {
            checkTrusted(chain, true);
        } catch (CertificateException e) {
            logger.warn("JSSOCSPTrustManager: Invalid SSL server certificate: " + e);
            throw e;
        } catch (Exception e) {
            logger.warn("JSSOCSPTrustManager: Unable to validate SSL server certificate: " + e);
            throw new CertificateException(e);
        }
    }

    @Override
    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
        /* Punt the problem to the regular JSSTrustManager.
         *
         * We have a mismatch between the Java and NSS interfaces here: the
         * underlying call we're using for NSS checks both the internal trust
         * store and what we pass in the NSS DB. However, NSS doesn't expose
         * the internally trusted certificates under the CERTCertificate
         * interface we need to construct certificates.
         */
        JSSTrustManager jtm = new JSSTrustManager();
        return jtm.getAcceptedIssuers();
    }
}
