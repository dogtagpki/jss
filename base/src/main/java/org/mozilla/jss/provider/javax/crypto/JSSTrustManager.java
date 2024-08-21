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
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.NotInitializedException;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.x509.CertificateSubjectName;
import org.mozilla.jss.netscape.security.x509.DNSName;
import org.mozilla.jss.netscape.security.x509.GeneralName;
import org.mozilla.jss.netscape.security.x509.GeneralNameInterface;
import org.mozilla.jss.netscape.security.x509.GeneralNames;
import org.mozilla.jss.netscape.security.x509.PKIXExtensions;
import org.mozilla.jss.netscape.security.x509.SubjectAlternativeNameExtension;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;
import org.mozilla.jss.pkcs11.PK11Cert;
import org.mozilla.jss.ssl.SSLCertificateApprovalCallback;
import org.mozilla.jss.ssl.SSLCertificateApprovalCallback.ValidityItem;
import org.mozilla.jss.ssl.SSLCertificateApprovalCallback.ValidityStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class JSSTrustManager implements X509TrustManager {

    public static final Logger logger = LoggerFactory.getLogger(JSSTrustManager.class);

    public static final String SERVER_AUTH_OID = "1.3.6.1.5.5.7.3.1";
    public static final String CLIENT_AUTH_OID = "1.3.6.1.5.5.7.3.2";

    private String hostname;
    private boolean allowMissingExtendedKeyUsage = false;
    private SSLCertificateApprovalCallback callback;

    public String getHostname() {
        return hostname;
    }

    public void setHostname(String hostname) {
        this.hostname = hostname;
    }

    public void configureAllowMissingExtendedKeyUsage(boolean allow) {
        allowMissingExtendedKeyUsage = allow;
    }

    public SSLCertificateApprovalCallback getCallback() {
        return callback;
    }

    public void setCallback(SSLCertificateApprovalCallback certCallback) {
        this.callback = certCallback;
    }

    public boolean isValidSAN(SubjectAlternativeNameExtension sanExt) throws Exception {

        logger.debug("JSSTrustManager: Checking hostname in SAN extension");

        if (sanExt == null) {
            return false;
        }

        GeneralNames generalNames = sanExt.getGeneralNames();
        Set<String> dnsNames = new HashSet<>();

        for (GeneralNameInterface generalName : generalNames) {

            if (generalName instanceof GeneralName) {
                generalName = ((GeneralName) generalName).unwrap();
            }

            if (generalName instanceof DNSName) {
                String dnsName = ((DNSName) generalName).getValue();
                logger.debug("JSSTrustManager: - dns: " + dnsName);
                dnsNames.add(dnsName.toLowerCase());
                continue;
            }
        }

        // TODO: add support for wildcards
        return dnsNames.contains(hostname);
    }

    public boolean isValidSubject(CertificateSubjectName subject) throws Exception {

        logger.debug("JSSTrustManager: Checking hostname in subject");

        X500Name dn = (X500Name) subject.get(CertificateSubjectName.DN_NAME);
        List<String> cns = dn.getAttributesForOid(X500Name.commonName_oid);

        if (cns == null) {
            return false;
        }

        for (String cn : cns) {
            logger.debug("JSSTrustManager: - cn: " + cn);
        }

        // TODO: add support for wildcards
        return cns.contains(hostname);
    }

    public void checkHostname(X509Certificate[] certChain, ValidityStatus status) throws Exception {

        if (hostname == null) {
            return;
        }

        // validating hostname on leaf cert only
        X509Certificate leafCert = certChain[certChain.length - 1];
        int depth = 0;

        X509CertImpl certImpl = new X509CertImpl(leafCert.getEncoded());
        SubjectAlternativeNameExtension sanExt = (SubjectAlternativeNameExtension) certImpl.getExtension(PKIXExtensions.SubjectAlternativeName_Id.toString());

        if (isValidSAN(sanExt)) {
            return;
        }

        X509CertInfo info = certImpl.getInfo();
        CertificateSubjectName subject = (CertificateSubjectName) info.get(X509CertInfo.SUBJECT);

        if (isValidSubject(subject)) {
            return;
        }

        status.addReason(ValidityStatus.BAD_CERT_DOMAIN, leafCert, depth);
    }

    public void checkCertChain(X509Certificate[] certChain, String keyUsage) throws Exception {

        logger.debug("JSSTrustManager: checkCertChain(" + keyUsage + ")");

        // sort cert chain from root to leaf
        // TODO: resolve incomplete chain
        certChain = Cert.sortCertificateChain(certChain);

        for (X509Certificate cert : certChain) {
            logger.debug("JSSTrustManager:  - " + cert.getSubjectX500Principal());
        }

        X509Certificate leafCert = certChain[certChain.length - 1];

        ValidityStatus status = new ValidityStatus();
        checkCertChain(certChain, keyUsage, status);

        Enumeration<ValidityItem> reasons = status.getReasons();
        if (!reasons.hasMoreElements()) {
            logger.debug("JSSTrustManager: Trusted cert: " + leafCert.getSubjectX500Principal());
            return;
        }

        if (callback != null && callback.approve(leafCert, status)) {
            logger.debug("JSSTrustManager: Approved cert: " + leafCert.getSubjectX500Principal());
            return;
        }

        // throw an exception based on the first issue
        ValidityItem issue = reasons.nextElement();
        X500Principal subject = issue.getCert().getSubjectX500Principal();

        // TODO: use enum
        switch (issue.getReason()) {
        case ValidityStatus.EXPIRED_CERTIFICATE:
            throw new CertificateExpiredException("Expired certificate: " + subject);
        case ValidityStatus.INADEQUATE_KEY_USAGE:
            throw new CertificateException("Inadequate key usage: " + subject);
        case ValidityStatus.UNKNOWN_ISSUER:
            throw new CertificateException("Unknown issuer: " + subject);
        case ValidityStatus.UNTRUSTED_ISSUER:
            throw new CertificateException("Untrusted issuer: " + subject);
        case ValidityStatus.BAD_CERT_DOMAIN:
            throw new CertificateException("Bad certificate domain: " + subject);
        default:
            throw new CertificateException("Invalid certificate: " + subject);
        }
    }

    public void checkCertChain(X509Certificate[] certChain, String keyUsage, ValidityStatus status) throws Exception {

        checkHostname(certChain, status);

        if (!isTrustedPeer(certChain)) {
            checkIssuerTrusted(certChain, status);
        }

        checkValidityDates(certChain, status);

        checkKeyUsage(certChain, keyUsage, status);
    }

    public boolean isTrustedPeer(X509Certificate[] certChain) throws Exception {

        // checking trust flags on leaf cert only
        X509Certificate leafCert = certChain[certChain.length - 1];
        logger.debug("JSSTrustManager: Checking trust flags of cert 0x" + leafCert.getSerialNumber().toString(16));

        if (! (leafCert instanceof org.mozilla.jss.crypto.X509Certificate)) {
            return false;
        }

        org.mozilla.jss.crypto.X509Certificate jssCert = (org.mozilla.jss.crypto.X509Certificate) leafCert;

        String trustFlags = jssCert.getTrustFlags();
        logger.debug("JSSTrustManager: - trust flags: " + trustFlags);

        int sslTrust = jssCert.getSSLTrust();
        return org.mozilla.jss.crypto.X509Certificate.isTrustFlagEnabled(
                org.mozilla.jss.crypto.X509Certificate.TRUSTED_PEER,
                sslTrust);
    }

    public void checkIssuerTrusted(X509Certificate[] certChain, ValidityStatus status) throws Exception {

        // get CA certs
        X509Certificate[] caCerts = getAcceptedIssuers();

        // validating signature from root to leaf
        for (int i = 0; i < certChain.length; i++) {
            X509Certificate cert = certChain[i];
            int depth = certChain.length - 1 - i;

            checkSignature(cert, caCerts, depth, status);

            // use the current cert as the CA cert for the next cert in the chain
            caCerts = new X509Certificate[] { cert };
        }
    }

    public void checkSignature(
            X509Certificate cert,
            X509Certificate[] caCerts,
            int depth,
            ValidityStatus status) throws Exception {

        logger.debug("JSSTrustManager: Checking signature of cert 0x" + cert.getSerialNumber().toString(16));
        logger.debug("JSSTrustManager: - subject: " + cert.getSubjectX500Principal());
        logger.debug("JSSTrustManager: - issuer: " + cert.getIssuerX500Principal());

        boolean[] aki = cert.getIssuerUniqueID();
        logger.debug("JSSTrustManager: - AKI: " + Arrays.toString(aki));

        X509Certificate issuer = null;
        for (X509Certificate caCert : caCerts) {

            logger.debug("JSSTrustManager: Checking against CA cert:");
            logger.debug("JSSTrustManager: - subject: " + caCert.getSubjectX500Principal());

            boolean[] ski = caCert.getSubjectUniqueID();
            logger.debug("JSSTrustManager: - SKI: " + Arrays.toString(ski));

            try {
                cert.verify(caCert.getPublicKey(), "Mozilla-JSS");
                issuer = caCert;
                break;
            } catch (Exception e) {
                logger.debug("JSSTrustManager: " + e.getClass().getName() + ": " + e.getMessage());
            }
        }

        if (issuer == null) {
            logger.debug("JSSTrustManager: Unknown issuer: " + cert.getIssuerX500Principal());

            status.addReason(ValidityStatus.UNKNOWN_ISSUER, cert, depth);

            return;
        }

        logger.debug("JSSTrustManager: Trusted issuer: " + issuer.getSubjectX500Principal());
    }

    public void checkValidityDates(X509Certificate[] certChain, ValidityStatus status) throws Exception {

        for (int i = 0; i < certChain.length; i++) {
            X509Certificate cert = certChain[i];
            int depth = certChain.length - 1 - i;

            logger.debug("JSSTrustManager: Checking validity dates of cert 0x" + cert.getSerialNumber().toString(16));
            logger.debug("JSSTrustManager: - not before: " + cert.getNotBefore());
            logger.debug("JSSTrustManager: - not after: " + cert.getNotAfter());

            try {
                cert.checkValidity();

            } catch (CertificateNotYetValidException e) {
                logger.debug("JSSTrustManager: Cert not yet valid: " + cert.getSubjectX500Principal());

                // NSS uses EXPIRED_CERTIFICATE for this case in CERT_CheckCertValidTimes()
                status.addReason(ValidityStatus.EXPIRED_CERTIFICATE, cert, depth);

            } catch (CertificateExpiredException e) {
                logger.debug("JSSTrustManager: Cert has expired: " + cert.getSubjectX500Principal());
                status.addReason(ValidityStatus.EXPIRED_CERTIFICATE, cert, depth);
            }
        }
    }

    public void checkKeyUsage(X509Certificate[] certChain, String keyUsage, ValidityStatus status) throws Exception {

        // validating key usage on leaf cert only
        X509Certificate cert = certChain[certChain.length - 1];
        int depth = 0;

        List<String> extendedKeyUsages = cert.getExtendedKeyUsage();
        logger.debug("JSSTrustManager: Checking key usage of cert 0x" + cert.getSerialNumber().toString(16));

        if (extendedKeyUsages != null) {
            for (String extKeyUsage : extendedKeyUsages) {
                logger.debug("JSSTrustManager: - " + extKeyUsage);
            }
        }

        boolean haveKeyUsage = extendedKeyUsages != null && extendedKeyUsages.contains(keyUsage);
        if (haveKeyUsage) {
            logger.debug("JSSTrustManager: Extended key usage found: " + keyUsage);
            return;
        }

        boolean allowedToSkip = extendedKeyUsages == null && allowMissingExtendedKeyUsage;
        if (allowedToSkip) {
            logger.debug("JSSTrustManager: Configured to allow null extended key usages field");
            return;
        }

        if (extendedKeyUsages == null) {
            logger.debug("JSSTrustManager: Missing extended key usage extension");

        } else {
            logger.debug("JSSTrustManager: Missing " + keyUsage + " key usage");
        }

        status.addReason(ValidityStatus.INADEQUATE_KEY_USAGE, cert, depth);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] certChain, String authType) throws CertificateException {

        logger.debug("JSSTrustManager: checkClientTrusted(" + authType + "):");

        try {
            checkCertChain(certChain, CLIENT_AUTH_OID);
            logger.debug("JSSTrustManager: SSL client certificate is valid");

        } catch (CertificateException e) {
            throw e;

        } catch (Exception e) {
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
            throw e;

        } catch (Exception e) {
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
                    logger.debug("JSSTrustManager: " + e.getClass().getName() + ": " + e.getMessage());
                }
            }

        } catch (NotInitializedException e) {
            logger.error("JSSTrustManager: Unable to get CryptoManager: " + e, e);
            throw new RuntimeException(e);
        }

        return caCerts.toArray(new X509Certificate[caCerts.size()]);
    }
}
