/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkcs7;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.IOException;
import org.mozilla.jss.asn1.*;
import org.mozilla.jss.pkix.primitive.*;
import org.mozilla.jss.util.Assert;

/**
 * An issuer name and serial number, used to uniquely identify a certificate.
 */
public class IssuerAndSerialNumber implements ASN1Value {

    ///////////////////////////////////////////////////////////////////////
    // Members
    ///////////////////////////////////////////////////////////////////////
    private Name issuer;
    private INTEGER serialNumber;
    private SEQUENCE sequence;

    ///////////////////////////////////////////////////////////////////////
    // Construction
    ///////////////////////////////////////////////////////////////////////

    // no default constructor
    private IssuerAndSerialNumber() { }

    /** 
     * Constructs an IssuerAndSerialNumber from its components.
     *
     * @param issuer Must not be null.
     * @param serialNumber must not be null.
     */
    public IssuerAndSerialNumber(Name issuer, INTEGER serialNumber) {
        if(issuer==null || serialNumber==null) {
            throw new IllegalArgumentException();
        }
        sequence = new SEQUENCE();
        this.issuer = issuer;
        sequence.addElement(issuer);
        this.serialNumber = serialNumber;
        sequence.addElement(serialNumber);
    }

    ///////////////////////////////////////////////////////////////////////
    // accessors
    ///////////////////////////////////////////////////////////////////////
    public Name getIssuer() {
        return issuer;
    }

    public INTEGER getSerialNumber() {
        return serialNumber;
    }

    ///////////////////////////////////////////////////////////////////////
    // DER encoding
    ///////////////////////////////////////////////////////////////////////
    static Tag TAG = SEQUENCE.TAG;
    public Tag getTag() {
        return TAG;
    }

    public void encode(OutputStream ostream) throws IOException {
        encode(TAG, ostream);
    }

    public void encode(Tag implicitTag, OutputStream ostream)
        throws IOException
    {
        sequence.encode(implicitTag, ostream);
    }

    /**
     * Returns a singleton template instance.
     */
    public static Template getTemplate() {
        return templateInstance;
    }
    private static Template templateInstance = new Template();

    /**
     * A template for decoding an IssuerAndSerialNumber from its BER encoding.
     */
    public static class Template implements ASN1Template {
        private SEQUENCE.Template seqt;

        public Template() {
            seqt = new SEQUENCE.Template();
            seqt.addElement( Name.getTemplate() );
            seqt.addElement( INTEGER.getTemplate() );
        }

        public boolean tagMatch(Tag tag) {
            return TAG.equals(tag);
        }

        public ASN1Value decode(InputStream istream)
            throws InvalidBERException, IOException
        {
            return decode(TAG, istream);
        }

        public ASN1Value decode(Tag implicitTag, InputStream istream)
            throws InvalidBERException, IOException
        {
            SEQUENCE seq = (SEQUENCE) seqt.decode(implicitTag, istream);

            Assert._assert(seq.size() == 2);

            return new IssuerAndSerialNumber(
                            (Name)      seq.elementAt(0),
                            (INTEGER)   seq.elementAt(1) );
        }
    }
}
