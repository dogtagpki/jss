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
package org.mozilla.jss.netscape.security.x509;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.mozilla.jss.netscape.security.pkcs.PKCS7;
import org.mozilla.jss.netscape.security.util.Cert;

public class CertificateChain implements Serializable {

    private List<X509Certificate> certs = new ArrayList<>();

    /**
     * Constructs an empty certificate chain.
     */
    public CertificateChain() {
    }

    /**
     * constructs a certificate chain from a certificate.
     *
     * @param cert a certificate
     */
    public CertificateChain(X509Certificate cert) {
        if (cert == null) {
            throw new IllegalArgumentException("Missing input certificate");
        }
        certs.add(cert);
    }

    /**
     * constructs a certificate chain from a X509 certificate array.
     *
     * @param certs a certificate array.
     */
    public CertificateChain(X509Certificate[] certs) {
        if (certs == null) {
            throw new IllegalArgumentException("Missing input certificates");
        }
        this.certs.addAll(Arrays.asList(certs));
    }

    /**
     * Returns the certificate list.
     *
     * @return The certificate list.
     */
    public List<X509Certificate> getCertificates() {
        return certs;
    }

    /**
     * returns the certificate at specified index in chain.
     *
     * @param index the index.
     * @return the X509 certificate at the given index.
     */
    public X509Certificate getCertificate(int index) {
        return certs.get(index);
    }

    /**
     * returns the first certificate in chain.
     *
     * @return the X509 certificate at the given index.
     */
    public X509Certificate getFirstCertificate() {
        return certs.get(0);
    }

    /**
     * returns the certificate chain as an array of X509 certificates.
     *
     * @return an array of X509 Certificates.
     */
    public X509Certificate[] getChain() {
        return certs.toArray(new X509Certificate[certs.size()]);
    }

    /**
     * Sorts certificate chain from root to leaf.
     */
    public void sort() throws Exception {
        X509Certificate[] certs = getChain();
        certs = Cert.sortCertificateChain(certs);
        this.certs.clear();
        this.certs.addAll(Arrays.asList(certs));
    }

    public void encode(OutputStream out)
            throws IOException {
        encode(out, true);
    }

    /**
     * encode in PKCS7 blob.
     */
    public void encode(OutputStream out, boolean sort) throws IOException {
        X509Certificate[] certs = getChain();
        PKCS7 p7 = new PKCS7(certs);
        p7.encodeSignedData(out, sort);
    }

    /**
     * decode from PKCS7 blob.
     */
    public void decode(InputStream in)
            throws IOException {
        PKCS7 p7 = new PKCS7(in);
        certs.clear();
        certs.addAll(Arrays.asList(p7.getCertificates()));
    }

    /**
     * for serialization
     */
    private void writeObject(java.io.ObjectOutputStream out)
            throws IOException {
        encode(out);
    }

    /**
     * for serialization
     */
    private void readObject(java.io.ObjectInputStream in)
            throws IOException {
        decode(in);
    }

    /**
     * Converts the certificate chain to a readable string.
     */
    public String toString() {

        if (certs.isEmpty()) {
            return "[]";
        }

        StringBuilder sb = new StringBuilder();
        sb.append("[");
        for (X509Certificate cert : certs) {
            sb.append(cert);
        }
        sb.append("]");

        return sb.toString();
    }
}
