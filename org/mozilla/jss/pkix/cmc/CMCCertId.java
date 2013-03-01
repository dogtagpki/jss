/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkix.cmc;

import org.mozilla.jss.asn1.*;
import java.io.*;

/**
 * CMC <i>CMCCertId</i>.
 * <pre>
 * The definition of IssuerSerial comes from RFC 3281.
 * CMCCertId ::= SEQUENCE {
 *      issuer      GeneralNames,
 *      serial      INTEGER 
 *      issuerUID   UniqueIdentifier OPTIONAL}
 * </pre>
 */
public class CMCCertId implements ASN1Value {

    ///////////////////////////////////////////////////////////////////////
    // Members and member access
    ///////////////////////////////////////////////////////////////////////
    private SEQUENCE issuer;
    private INTEGER serial;
    private BIT_STRING issuerUID;
    private SEQUENCE sequence;

    /**
     * Returns the <code>issuer</code> field as an <code>SEQUENCE of
     * ANY</code>. The actual type of the field is <i>GeneralNames</i>.
     */
    public SEQUENCE getIssuer() {
        return issuer;
    }

    /**
     * Returns the <code>serial</code> field.
     */
    public INTEGER getSerial() {
        return serial;
    }

    /**
     * Returns the <code>issuerUID</code> field.
     */
    public BIT_STRING getIssuerUID() {
        return issuerUID;
    }

    ///////////////////////////////////////////////////////////////////////
    // Constructors
    ///////////////////////////////////////////////////////////////////////
    private CMCCertId() { }

    /**
     * Constructs a new <code>CMCCertId</code> from its components. The
     * uniqueIdentifier component may be <code>null</code>.
     */
    public CMCCertId(SEQUENCE issuer, INTEGER serial, BIT_STRING issuerUID) {
        if (issuer == null || serial == null) {
            throw new IllegalArgumentException(
                "parameter to CMCCertId constructor is null");
        }
        if (issuer.size() == 0) {
            throw new IllegalArgumentException(
                "issuer parameter to CMCCertId constructor is empty");
        }
        sequence = new SEQUENCE();

        this.issuer = issuer;
        sequence.addElement(issuer);

        this.serial = serial;
        sequence.addElement(serial);

        if (issuerUID != null) {
            sequence.addElement(issuerUID);
        }
    }

    /**
     * Constructs a new <code>CMCCertId</code> from its components. The
     * issuerUID component may be <code>null</code>.
     */
    public CMCCertId(ANY issuer, INTEGER serial, BIT_STRING issuerUID) {
        if (issuer == null || serial == null) {
            throw new IllegalArgumentException(
                "parameter to CMCCertId constructor is null");
        }
        sequence = new SEQUENCE();
        this.issuer = new SEQUENCE();
        this.issuer.addElement(issuer);
        sequence.addElement(this.issuer);

        this.serial = serial;
        sequence.addElement(serial);

        if (issuerUID != null) {
            sequence.addElement(issuerUID);
        }
    }

    ///////////////////////////////////////////////////////////////////////
    // encoding/decoding
    ///////////////////////////////////////////////////////////////////////
    private static final Tag TAG = SEQUENCE.TAG;
    public Tag getTag() {
        return TAG;
    }

    public void encode(OutputStream ostream) throws IOException {
        sequence.encode(ostream);
    }

    public void encode(Tag implicitTag, OutputStream ostream)
            throws IOException {
        sequence.encode(implicitTag, ostream);
    }

    private static final Template templateInstance = new Template();
    public static Template getTemplate() {
        return templateInstance;
    }

    /**
     * A Template for decoding a <code>CMCCertId</code>.
     */
    public static class Template implements ASN1Template {
        private SEQUENCE.Template seqt;

        public Template() {
            seqt = new SEQUENCE.Template();
            seqt.addElement(new SEQUENCE.OF_Template(ANY.getTemplate()));
            seqt.addElement( INTEGER.getTemplate() );
            seqt.addOptionalElement(BIT_STRING.getTemplate());
        }

        public boolean tagMatch(Tag tag) {
            return TAG.equals(tag);
        }

        public ASN1Value decode(InputStream istream)
                throws InvalidBERException, IOException {
            return decode(TAG, istream);
        }

        public ASN1Value decode(Tag implicitTag, InputStream istream)
                throws InvalidBERException, IOException {
            SEQUENCE seq = (SEQUENCE) seqt.decode(implicitTag, istream);

            return new CMCCertId((SEQUENCE)seq.elementAt(0),
                                 (INTEGER)seq.elementAt(1),
                                 (BIT_STRING)seq.elementAt(2));
        }
    }
}
