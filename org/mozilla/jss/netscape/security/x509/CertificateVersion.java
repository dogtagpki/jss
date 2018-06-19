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
import java.util.Enumeration;
import java.util.Vector;

import org.mozilla.jss.netscape.security.util.BigInt;
import org.mozilla.jss.netscape.security.util.DerInputStream;
import org.mozilla.jss.netscape.security.util.DerOutputStream;
import org.mozilla.jss.netscape.security.util.DerValue;

/**
 * This class defines the version of the X509 Certificate.
 *
 * @author Amit Kapoor
 * @author Hemma Prafullchandra
 * @version 1.8
 * @see CertAttrSet
 */
public class CertificateVersion implements CertAttrSet {
    /**
     * X509Certificate Version 1
     */
    public static final int V1 = 0;
    /**
     * X509Certificate Version 2
     */
    public static final int V2 = 1;
    /**
     * X509Certificate Version 3
     */
    public static final int V3 = 2;
    /**
     * Identifier for this attribute, to be used with the
     * get, set, delete methods of Certificate, x509 type.
     */
    public static final String IDENT = "x509.info.version";
    /**
     * Sub attributes name for this CertAttrSet.
     */
    public static final String NAME = "version";
    public static final String VERSION = "number";

    // Private data members
    int version = V1;

    // Returns the version number.
    private int getVersion() {
        return (version);
    }

    // Construct the class from the passed DerValue
    private void construct(DerValue derVal) throws IOException {
        if (derVal.isConstructed() && derVal.isContextSpecific()) {
            derVal = derVal.data.getDerValue();
            version = derVal.getInteger().toInt();
            if (derVal.data.available() != 0) {
                throw new IOException("X.509 version, bad format");
            }
        }
    }

    /**
     * The default constructor for this class,
     * sets the version to 0 (i.e. X.509 version 1).
     */
    public CertificateVersion() {
        version = V1;
    }

    /**
     * The constructor for this class for the required version.
     *
     * @param version the version for the certificate.
     * @exception IOException if the version is not valid.
     */
    public CertificateVersion(int version) throws IOException {

        // check that it is a valid version
        if (version == V1 || version == V2 || version == V3)
            this.version = version;
        else {
            throw new IOException("X.509 Certificate version " +
                                   version + " not supported.\n");
        }
    }

    /**
     * Create the object, decoding the values from the passed DER stream.
     *
     * @param in the DerInputStream to read the CertificateVersion from.
     * @exception IOException on decoding errors.
     */
    public CertificateVersion(DerInputStream in) throws IOException {
        version = V1;
        DerValue derVal = in.getDerValue();

        construct(derVal);
    }

    /**
     * Create the object, decoding the values from the passed stream.
     *
     * @param in the InputStream to read the CertificateVersion from.
     * @exception IOException on decoding errors.
     */
    public CertificateVersion(InputStream in) throws IOException {
        version = V1;
        DerValue derVal = new DerValue(in);

        construct(derVal);
    }

    /**
     * Create the object, decoding the values from the passed DerValue.
     *
     * @param val the Der encoded value.
     * @exception IOException on decoding errors.
     */
    public CertificateVersion(DerValue val) throws IOException {
        version = V1;

        construct(val);
    }

    /**
     * Return the version number of the certificate.
     */
    public String toString() {
        return ("Version: V" + (version + 1));
    }

    /**
     * Encode the CertificateVersion period in DER form to the stream.
     *
     * @param out the OutputStream to marshal the contents to.
     * @exception IOException on errors.
     */
    public void encode(OutputStream out) throws IOException {
        // Nothing for default
        if (version == V1) {
            return;
        }
        try (DerOutputStream tmp = new DerOutputStream();
                DerOutputStream seq = new DerOutputStream()) {
            tmp.putInteger(new BigInt(version));

            seq.write(DerValue.createTag(DerValue.TAG_CONTEXT, true, (byte) 0),
                    tmp);

            out.write(seq.toByteArray());
        }
    }

    /**
     * Decode the CertificateVersion period in DER form from the stream.
     *
     * @param in the InputStream to unmarshal the contents from.
     * @exception IOException on errors.
     */
    public void decode(InputStream in) throws IOException {
        DerValue derVal = new DerValue(in);
        construct(derVal);
    }

    /**
     * Set the attribute value.
     */
    public void set(String name, Object obj) throws IOException {
        if (!(obj instanceof Integer)) {
            throw new IOException("Attribute must be of type Integer.");
        }
        if (name.equalsIgnoreCase(VERSION)) {
            version = ((Integer) obj).intValue();
        } else {
            throw new IOException("Attribute name not recognized by " +
                                  "CertAttrSet: CertificateVersion.");
        }
    }

    /**
     * Get the attribute value.
     */
    public Object get(String name) throws IOException {
        if (name.equalsIgnoreCase(VERSION)) {
            return (Integer.valueOf(getVersion()));
        } else {
            throw new IOException("Attribute name not recognized by " +
                                  "CertAttrSet: CertificateVersion.");
        }
    }

    /**
     * Delete the attribute value.
     */
    public void delete(String name) throws IOException {
        if (name.equalsIgnoreCase(VERSION)) {
            version = V1;
        } else {
            throw new IOException("Attribute name not recognized by " +
                                  "CertAttrSet: CertificateVersion.");
        }
    }

    /**
     * Return an enumeration of names of attributes existing within this
     * attribute.
     */
    public Enumeration<String> getAttributeNames() {
        Vector<String> elements = new Vector<String>();
        elements.addElement(VERSION);

        return (elements.elements());
    }

    /**
     * Return the name of this attribute.
     */
    public String getName() {
        return (NAME);
    }

    /**
     * Compare versions.
     */
    public int compare(int vers) {
        return (version - vers);
    }
}
