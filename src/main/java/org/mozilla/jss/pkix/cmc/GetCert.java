/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkix.cmc;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.mozilla.jss.asn1.ANY;
import org.mozilla.jss.asn1.ASN1Template;
import org.mozilla.jss.asn1.ASN1Value;
import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.asn1.Tag;

/**
 * CMC <i>GetCert</i>.
 * <pre>
 * GetCert ::= SEQUENCE {
 *      issuerName      GeneralName,
 *      serialNumber    INTEGER }
 * </pre>
 */
public class GetCert implements ASN1Value {

    ///////////////////////////////////////////////////////////////////////
    // Members and member access
    ///////////////////////////////////////////////////////////////////////
    private ANY issuerName;
    private INTEGER serialNumber;
    private SEQUENCE sequence;

    /**
     * Returns the <code>issuerName</code> field as an <code>ANY</code>.
     * The actual type of the field is <i>GeneralName</i>.
     */
    public ANY getIssuer() {
        return issuerName;
    }

    /**
     * Returns the <code>serialNumber</code> field.
     */
    public INTEGER getSerialNumber() {
        return serialNumber;
    }

    ///////////////////////////////////////////////////////////////////////
    // Constructors
    ///////////////////////////////////////////////////////////////////////

    /**
     * Constructs a new <code>GetCert</code> from its components.  Neither
     * component may be <code>null</code>.
     */
    public GetCert(ANY issuerName, INTEGER serialNumber) {
        if( issuerName == null || serialNumber == null ) {
            throw new IllegalArgumentException(
                "parameter to GetCert constructor is null");
        }
        sequence = new SEQUENCE();

        this.issuerName = issuerName;
        sequence.addElement(issuerName);

        this.serialNumber = serialNumber;
        sequence.addElement(serialNumber);
    }

    ///////////////////////////////////////////////////////////////////////
    // encoding/decoding
    ///////////////////////////////////////////////////////////////////////
    private static final Tag TAG = SEQUENCE.TAG;
    @Override
    public Tag getTag() {
        return TAG;
    }

    @Override
    public void encode(OutputStream ostream) throws IOException {
        sequence.encode(ostream);
    }

    @Override
    public void encode(Tag implicitTag, OutputStream ostream)
            throws IOException {
        sequence.encode(implicitTag, ostream);
    }

    private static final Template templateInstance = new Template();
    public static Template getTemplate() {
        return templateInstance;
    }

    /**
     * A Template for decoding a <code>GetCert</code>.
     */
    public static class Template implements ASN1Template {
        private SEQUENCE.Template seqt;

        public Template() {
            seqt = new SEQUENCE.Template();
            seqt.addElement( ANY.getTemplate() );
            seqt.addElement( INTEGER.getTemplate() );
         }

        @Override
        public boolean tagMatch(Tag tag) {
            return TAG.equals(tag);
        }

        @Override
        public ASN1Value decode(InputStream istream)
                throws InvalidBERException, IOException {
            return decode(TAG, istream);
        }

        @Override
        public ASN1Value decode(Tag implicitTag, InputStream istream)
                throws InvalidBERException, IOException {
            SEQUENCE seq = (SEQUENCE) seqt.decode(implicitTag, istream);

            return new GetCert( (ANY)       seq.elementAt(0),
                                (INTEGER)   seq.elementAt(1) );
        }
    }
}
