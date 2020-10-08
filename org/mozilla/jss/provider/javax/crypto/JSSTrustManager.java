/* BEGIN COPYRIGHT BLOCK
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * Copyright (C) 2017 Red Hat, Inc.
 * All rights reserved.
 * END COPYRIGHT BLOCK */

package org.mozilla.jss.provider.javax.crypto;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import javax.net.ssl.X509TrustManager;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.NotInitializedException;
import org.mozilla.jss.pkcs11.PK11Cert;
import org.mozilla.jss.netscape.security.util.Cert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class JSSTrustManager implements X509TrustManager {

    final static Logger logger = LoggerFactory.getLogger(JSSTrustManager.class);

    final static String SERVER_AUTH_OID = "1.3.6.1.5.5.7.3.1";
    final static String CLIENT_AUTH_OID = "1.3.6.1.5.5.7.3.2";

    public boolean allowMissingExtendedKeyUsage = false;

    public void configureAllowMissingExtendedKeyUsage(boolean allow) {
        allowMissingExtendedKeyUsage = allow;
    }

    public void checkCertChain(X509Certificate[] certChain, String keyUsage) throws Exception {

        logger.debug("JSSTrustManager: checkCertChain(" + keyUsage + ")");

        // sort cert chain from root to leaf
        certChain = Cert.sortCertificateChain(certChain);

        for (X509Certificate cert : certChain) {
            logger.debug("JSSTrustManager:  - " + cert.getSubjectDN());
        }

        // get CA certs
        X509Certificate[] caCerts = getAcceptedIssuers();

        // validating cert chain from root to leaf
        for (int i = 0; i < certChain.length; i++) {

            X509Certificate cert = certChain[i];

            // validating key usage on leaf cert only
            String usage;
            if (i == certChain.length - 1) {
                usage = keyUsage;
            } else {
                usage = null;
            }

            checkCert(cert, caCerts, usage);

            // use the current cert as the CA cert for the next cert in the chain
            caCerts = new X509Certificate[] { cert };
        }
    }

    public void checkCert(X509Certificate cert, X509Certificate[] caCerts, String keyUsage) throws Exception {

        logger.debug("JSSTrustManager: checkCert(" + cert.getSubjectDN() + "):");

        boolean[] aki = cert.getIssuerUniqueID();
        logger.debug("JSSTrustManager: cert AKI: " + Arrays.toString(aki));

        X509Certificate issuer = null;
        for (X509Certificate caCert : caCerts) {

            boolean[] ski = caCert.getSubjectUniqueID();
            logger.debug("JSSTrustManager: SKI of " + caCert.getSubjectDN() + ": " + Arrays.toString(ski));

            try {
                cert.verify(caCert.getPublicKey(), "Mozilla-JSS");
                issuer = caCert;
                break;
            } catch (Exception e) {
                logger.debug("JSSTrustManager: invalid certificate: " + e);
            }
        }

        if (issuer == null) {
            throw new CertificateException("Unable to validate signature: " + cert.getSubjectDN());
        }

        logger.debug("JSSTrustManager: cert signed by " + issuer.getSubjectDN());

        logger.debug("JSSTrustManager: checking validity range:");
        logger.debug("JSSTrustManager:  - not before: " + cert.getNotBefore());
        logger.debug("JSSTrustManager:  - not after: " + cert.getNotAfter());
        cert.checkValidity();

        if (keyUsage != null) {

            List<String> extendedKeyUsages = cert.getExtendedKeyUsage();
            logger.debug("JSSTrustManager: checking extended key usages:");

            if (extendedKeyUsages != null) {
                for (String extKeyUsage : extendedKeyUsages) {
                    logger.debug("JSSTrustManager:  - " + extKeyUsage);
                }
            }

            boolean haveKeyUsage = extendedKeyUsages != null && extendedKeyUsages.contains(keyUsage);
            boolean allowedToSkip = extendedKeyUsages == null && allowMissingExtendedKeyUsage;
            if (haveKeyUsage) {
                logger.debug("JSSTrustManager: extended key usage found: " + keyUsage);
            } else if (allowedToSkip) {
                logger.debug("JSSTrustManager: configured to allow null extended key usages field");
            } else {
                String msg = "Missing EKU: " + keyUsage +
                    ". Certificate with subject DN `" + cert.getSubjectDN() + "` had ";
                if (extendedKeyUsages == null) {
                    msg += "no EKU extension";
                } else {
                    msg += "EKUs { ";
                    boolean first = true;
                    for (String eku : extendedKeyUsages) {
                        if (!first) msg += " , ";
                        msg += eku;
                        first = false;
                    }
                    msg += " }";
                }
                msg += ".  class = " + cert.getClass();
                throw new CertificateException(msg);
            }
        }
    }

    @Override
    public void checkClientTrusted(X509Certificate[] certChain, String authType) throws CertificateException {

        logger.debug("JSSTrustManager: checkClientTrusted(" + authType + "):");

        try {
            checkCertChain(certChain, CLIENT_AUTH_OID);
            logger.debug("JSSTrustManager: SSL client certificate is valid");

        } catch (CertificateException e) {
            logger.warn("JSSTrustManager: Invalid SSL client certificate: " + e);
            throw e;

        } catch (Exception e) {
            logger.warn("JSSTrustManager: Unable to validate certificate: " + e);
            throw new CertificateException(e);
        }
    }

    @Override
    public void checkServerTrusted(X509Certificate[] certChain, String authType) throws CertificateException {

        logger.debug("JSSTrustManager: checkServerTrusted(" + certChain.length + ", " + authType + "):");

        try {
            checkCertChain(certChain, SERVER_AUTH_OID);
            logger.debug("JSSTrustManager: SSL server certificate is valid");

        } catch (CertificateException e) {
            logger.warn("JSSTrustManager: Invalid SSL server certificate: " + e);
            throw e;

        } catch (Exception e) {
            logger.warn("JSSTrustManager: Unable to validate SSL server certificate: " + e);
            throw new CertificateException(e);
        }
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {

        logger.debug("JSSTrustManager: getAcceptedIssuers():");

        Collection<X509Certificate> caCerts = new ArrayList<>();

        try {
            CryptoManager manager = CryptoManager.getInstance();
            for (org.mozilla.jss.crypto.X509Certificate cert : manager.getCACerts()) {
                logger.debug("JSSTrustManager:  - " + cert.getSubjectDN());

                try {
                    PK11Cert caCert = (PK11Cert) cert;
                    caCert.checkValidity();
                    caCerts.add(caCert);

                } catch (Exception e) {
                    logger.debug("JSSTrustManager: invalid CA certificate: " + e);
                }
            }

        } catch (NotInitializedException e) {
            logger.error("JSSTrustManager: Unable to get CryptoManager: " + e, e);
            throw new RuntimeException(e);
        }

        return caCerts.toArray(new X509Certificate[caCerts.size()]);
    }
}
