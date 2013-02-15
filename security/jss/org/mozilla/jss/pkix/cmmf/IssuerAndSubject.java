/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkix.cmmf;

import org.mozilla.jss.asn1.*;
import java.io.*;

/**
 * CMMF <i>IssuerAndSubject</i>.
 * <pre>
 * IssuerAndSubject ::= SEQUENCE {
 *      issuer          Name,
 *      subject         Name,
 *      certReqId       INTEGER OPTIONAL }
 * </pre>
 */
public class IssuerAndSubject implements ASN1Value {

    ///////////////////////////////////////////////////////////////////////
    // members and member access
    ///////////////////////////////////////////////////////////////////////
    private ANY issuer;
    private ANY subject;
    private INTEGER certReqId; // may be null
    private SEQUENCE sequence;

    /**
     * Returns the <code>issuer</code> field.
     */
    public ANY getIssuer() {
        return issuer;
    }

    /**
     * Returns the <code>subject</code> field.
     */
    public ANY getSubject() {
        return subject;
    }

    /**
     * Returns the <code>certReqId</code> field, which may be <code>null</code>.
     */
    public INTEGER getCertReqId() {
        return certReqId;
    }

    ///////////////////////////////////////////////////////////////////////
    // Constructors
    ///////////////////////////////////////////////////////////////////////

    private IssuerAndSubject() { }

    public IssuerAndSubject(ANY issuer, ANY subject, INTEGER certReqId) {
        if( issuer==null || subject==null ) {
            throw new IllegalArgumentException(
                "parameter to IssuerAndSubject constructor is null");
        }

        sequence = new SEQUENCE();

        this.issuer = issuer;
        sequence.addElement(issuer);
        this.subject = subject;
        sequence.addElement(subject);
        this.certReqId = certReqId;
        sequence.addElement(certReqId);
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
     * A Template for decoding an <code>IssuerAndSubject</code>.
     */
    public static class Template implements ASN1Template {

        private SEQUENCE.Template seqt;

        public Template() {
            seqt = new SEQUENCE.Template();

            seqt.addElement( ANY.getTemplate() );
            seqt.addElement( ANY.getTemplate() );
            seqt.addOptionalElement( INTEGER.getTemplate() );
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

            return new IssuerAndSubject( (ANY) seq.elementAt(0),
                                         (ANY) seq.elementAt(1),
                                         (INTEGER) seq.elementAt(2) );
        }
    }
}
