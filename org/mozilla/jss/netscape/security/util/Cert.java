// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package org.mozilla.jss.netscape.security.util;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang.ArrayUtils;
import org.mozilla.jss.crypto.SignatureAlgorithm;
import org.mozilla.jss.netscape.security.pkcs.PKCS7;
import org.mozilla.jss.netscape.security.x509.X509CRLImpl;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Cert {

    private static Logger logger = LoggerFactory.getLogger(Cert.class);

    public static final String HEADER = "-----BEGIN CERTIFICATE-----";
    public static final String FOOTER = "-----END CERTIFICATE-----";

    public static final String PKCS7_HEADER = "-----BEGIN PKCS7-----";
    public static final String PKCS7_FOOTER = "-----END PKCS7-----";

    // From https://www.rfc-editor.org/rfc/rfc7468.txt
    public static final String REQUEST_HEADER = "-----BEGIN CERTIFICATE REQUEST-----";
    public static final String REQUEST_FOOTER = "-----END CERTIFICATE REQUEST-----";

    public static SignatureAlgorithm mapAlgorithmToJss(String algname) {
        if (algname.equals("MD5withRSA"))
            return SignatureAlgorithm.RSASignatureWithMD5Digest;
        else if (algname.equals("MD2withRSA"))
            return SignatureAlgorithm.RSASignatureWithMD2Digest;
        else if (algname.equals("SHA1withRSA"))
            return SignatureAlgorithm.RSASignatureWithSHA1Digest;
        else if (algname.equals("SHA1withDSA"))
            return SignatureAlgorithm.DSASignatureWithSHA1Digest;
        else if (algname.equals("SHA256withRSA"))
            return SignatureAlgorithm.RSASignatureWithSHA256Digest;
        else if (algname.equals("SHA384withRSA"))
            return SignatureAlgorithm.RSASignatureWithSHA384Digest;
        else if (algname.equals("SHA512withRSA"))
            return SignatureAlgorithm.RSASignatureWithSHA512Digest;
        else if (algname.equals("SHA1withEC"))
            return SignatureAlgorithm.ECSignatureWithSHA1Digest;
        else if (algname.equals("SHA256withEC"))
            return SignatureAlgorithm.ECSignatureWithSHA256Digest;
        else if (algname.equals("SHA384withEC"))
            return SignatureAlgorithm.ECSignatureWithSHA384Digest;
        else if (algname.equals("SHA512withEC"))
            return SignatureAlgorithm.ECSignatureWithSHA512Digest;
       else if (algname.equals("SHA256withRSA/PSS"))
            return SignatureAlgorithm.RSAPSSSignatureWithSHA256Digest;
        else if (algname.equals("SHA384withRSA/PSS"))
            return SignatureAlgorithm.RSAPSSSignatureWithSHA384Digest;
        else if (algname.equals("SHA512withRSA/PSS"))
            return SignatureAlgorithm.RSAPSSSignatureWithSHA512Digest;

        return null;
    }

    public static String stripBrackets(String s) {
        if (s == null) {
            return s;
        }

        if (s.startsWith(HEADER) && s.endsWith(FOOTER)) {
            return s.substring(HEADER.length(), s.length() - FOOTER.length());
        }

        if (s.startsWith(PKCS7_HEADER) && s.endsWith(PKCS7_FOOTER)) {
            return s.substring(PKCS7_HEADER.length(), s.length() - PKCS7_FOOTER.length());
        }

        // To support Thawte's header and footer
        if ((s.startsWith("-----BEGIN PKCS #7 SIGNED DATA-----")) &&
                (s.endsWith("-----END PKCS #7 SIGNED DATA-----"))) {
            return (s.substring(35, (s.length() - 33)));
        }

        return s;
    }

    public static String stripCRLBrackets(String s) {
        if (s == null) {
            return s;
        }
        if ((s.startsWith("-----BEGIN CERTIFICATE REVOCATION LIST-----")) &&
                (s.endsWith("-----END CERTIFICATE REVOCATION LIST-----"))) {
            return (s.substring(43, (s.length() - 41)));
        }
        return s;
    }

    public static String stripCertBrackets(String s) {
        return stripBrackets(s);
    }

    // private static BASE64Decoder mDecoder = new BASE64Decoder();
    public static X509CertImpl mapCert(String mime64)
            throws IOException {
        mime64 = stripCertBrackets(mime64.trim());
        String newval = normalizeCertStr(mime64);
        // byte rawPub[] = mDecoder.decodeBuffer(newval);
        byte rawPub[] = Utils.base64decode(newval);
        X509CertImpl cert = null;

        try {
            cert = new X509CertImpl(rawPub);
        } catch (CertificateException e) {
        }
        return cert;
    }

    public static X509Certificate[] mapCertFromPKCS7(String mime64)
            throws IOException {
        mime64 = stripCertBrackets(mime64.trim());
        String newval = normalizeCertStr(mime64);
        // byte rawPub[] = mDecoder.decodeBuffer(newval);
        byte rawPub[] = Utils.base64decode(newval);
        PKCS7 p7 = null;

        try {
            p7 = new PKCS7(rawPub);
        } catch (Exception e) {
            throw new IOException("p7 is null");
        }
        return p7.getCertificates();
    }

    public static X509CRL mapCRL(String mime64)
            throws IOException {
        mime64 = stripCRLBrackets(mime64.trim());
        String newval = normalizeCertStr(mime64);
        // byte rawPub[] = mDecoder.decodeBuffer(newval);
        byte rawPub[] = Utils.base64decode(newval);
        X509CRL crl = null;

        try {
            crl = new X509CRLImpl(rawPub);
        } catch (Exception e) {
        }
        return crl;
    }

    public static X509CRL mapCRL1(String mime64)
            throws IOException {
        mime64 = stripCRLBrackets(mime64.trim());

        byte rawPub[] = Utils.base64decode(mime64);
        X509CRL crl = null;

        try {
            crl = new X509CRLImpl(rawPub);
        } catch (Exception e) {
            throw new IOException(e.toString());
        }
        return crl;
    }

    public static String normalizeCertStr(String s) {
        StringBuffer val = new StringBuffer();

        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) == '\n') {
                continue;
            } else if (s.charAt(i) == '\r') {
                continue;
            } else if (s.charAt(i) == '"') {
                continue;
            } else if (s.charAt(i) == ' ') {
                continue;
            }
            val.append(s.charAt(i));
        }
        return val.toString();
    }

    public static String normalizeCertStrAndReq(String s) {
        StringBuffer val = new StringBuffer();

        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) == '\n') {
                continue;
            } else if (s.charAt(i) == '\r') {
                continue;
            } else if (s.charAt(i) == '"') {
                continue;
            }
            val.append(s.charAt(i));
        }
        return val.toString();
    }

    public static byte[] parseCertificate(String cert) {
        String encoded = normalizeCertStrAndReq(cert);
        String b64 = stripBrackets(encoded);
        return Utils.base64decode(b64);
    }

    /**
     * Sorts certificate chain from root to leaf.
     *
     * This method sorts an array of certificates (e.g. from a PKCS #7
     * data) that represents a certificate chain from root to leaf
     * according to the subject DNs and issuer DNs.
     *
     * The input array is a set of certificates that are part of a
     * chain but not in specific order.
     *
     * The result is a new array that contains the certificate chain
     * sorted from root to leaf. The input array is unchanged.
     *
     * @param certs input array of certificates
     * @return new array containing sorted certificates
     */
    public static java.security.cert.X509Certificate[] sortCertificateChain(java.security.cert.X509Certificate[] certs) throws Exception {

        if (certs == null) {
            return null;
        }

        if (certs.length == 0) {
            return certs;
        }

        // lookup map: subject DN -> cert
        Map<String, java.security.cert.X509Certificate> certMap = new LinkedHashMap<>();

        // hierarchy map: subject DN -> issuer DN
        Map<String, String> parentMap = new HashMap<>();

        // reverse hierarchy map: issuer DN -> subject DN
        Map<String, String> childMap = new HashMap<>();

        // build maps
        for (java.security.cert.X509Certificate cert : certs) {

            String subjectDN = cert.getSubjectDN().toString();
            String issuerDN = cert.getIssuerDN().toString();

            if (certMap.containsKey(subjectDN)) {
                throw new Exception("Duplicate certificate: " + subjectDN);
            }

            certMap.put(subjectDN, cert);

            // ignore self-signed certificate
            if (subjectDN.equals(issuerDN)) continue;

            if (childMap.containsKey(issuerDN)) {
                throw new Exception("Branched chain: " + issuerDN);
            }

            parentMap.put(subjectDN, issuerDN);
            childMap.put(issuerDN, subjectDN);
        }

        if (logger.isDebugEnabled()) {
            logger.debug("Certificates:");
            for (String subjectDN : certMap.keySet()) {
                logger.debug(" - " + subjectDN);

                String parent = parentMap.get(subjectDN);
                if (parent != null) logger.debug("   parent: " + parent);

                String child = childMap.get(subjectDN);
                if (child != null) logger.debug("   child: " + child);
            }
        }

        // find leaf cert by removing certs that has a child
        List<String> leafCerts = new ArrayList<>();
        leafCerts.addAll(certMap.keySet());
        leafCerts.removeAll(childMap.keySet());

        if (leafCerts.isEmpty()) {
            throw new Exception("Unable to find leaf certificate");
        }

        if (leafCerts.size() > 1) {
            StringBuilder sb = new StringBuilder();
            for (String subjectDN : leafCerts) {
                if (sb.length() > 0) sb.append(", ");
                sb.append("[" + subjectDN + "]");
            }
            throw new Exception("Multiple leaf certificates: " + sb);
        }

        // build sorted chain
        LinkedList<java.security.cert.X509Certificate> chain = new LinkedList<>();

        // start from leaf
        String current = leafCerts.get(0);

        while (current != null) {

            java.security.cert.X509Certificate cert = certMap.get(current);

            if (cert == null) {
                // incomplete chain
                break;
            }

            // add to the beginning of chain
            chain.addFirst(cert);

            // follow parent to root
            current = parentMap.get(current);
        }

        return chain.toArray(new java.security.cert.X509Certificate[chain.size()]);
    }

    public static java.security.cert.X509Certificate[] sortCertificateChain(
            java.security.cert.X509Certificate[] certs,
            boolean reverse) throws Exception {

        certs = sortCertificateChain(certs);

        if (reverse) {
            ArrayUtils.reverse(certs);
        }

        return certs;
    }
}
