/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkix.cmc;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.mozilla.jss.asn1.ASN1Template;
import org.mozilla.jss.asn1.ASN1Value;
import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.asn1.Tag;
import org.mozilla.jss.pkcs10.CertificationRequest;

/**
 * CMC <i>TaggedCertificationRequest</i>:
 * <pre>
 *   TaggedCertificationRequest ::= SEQUENCE {
 *       bodyPartID            BodyPartID,
 *       certificationRequest  CertificationRequest
 *   }
 *   bodyIdMax INTEGER ::= 4294967295
 *
 *   BodyPartID ::= INTEGER(0..bodyIdMax)
 * </pre>
 */
public class TaggedCertificationRequest implements ASN1Value {
	public static final INTEGER BODYIDMAX = new INTEGER("4294967295");

    ///////////////////////////////////////////////////////////////////////
    // Members
    ///////////////////////////////////////////////////////////////////////
    private SEQUENCE sequence;
    private INTEGER bodyPartID;
	private CertificationRequest certificationRequest;

    ///////////////////////////////////////////////////////////////////////
    // Construction
    ///////////////////////////////////////////////////////////////////////

    /**
     * Constructs a TaggedCertificationRequest from its components.
     *
     * @param bodyPartID the identifier.
     * @param certificationRequest the pkcs10 request.
     */
    public TaggedCertificationRequest(INTEGER bodyPartID, CertificationRequest certificationRequest) {
        sequence = new SEQUENCE();
        assert(bodyPartID.compareTo(BODYIDMAX) <= 0);
        this.bodyPartID = bodyPartID;
        sequence.addElement(bodyPartID);
        this.certificationRequest = certificationRequest;
        sequence.addElement(certificationRequest);
	}

    ///////////////////////////////////////////////////////////////////////
    // accessors
    ///////////////////////////////////////////////////////////////////////

    public CertificationRequest getCertificationRequest() {
        return certificationRequest;
    }

    public INTEGER getBodyPartID() {
        return bodyPartID;
    }

    ///////////////////////////////////////////////////////////////////////
    // DER encoding/decoding
    ///////////////////////////////////////////////////////////////////////
    public static final Tag TAG = SEQUENCE.TAG;
    @Override
    public Tag getTag() {
        return TAG;
    }

    @Override
    public void encode(OutputStream ostream) throws IOException {
        encode(TAG, ostream);
    }

    @Override
    public void encode(Tag implicitTag, OutputStream ostream)
        throws IOException
    {
        sequence.encode(implicitTag, ostream);
    }

    private static final Template templateInstance = new Template();
    public static Template getTemplate() {
        return templateInstance;
    }

    /**
     * A template for decoding an TaggedCertificationRequest from its BER encoding.
     */
    public static class Template implements ASN1Template {
        private SEQUENCE.Template seqt;

        public Template() {
            seqt = new SEQUENCE.Template();
            seqt.addElement( INTEGER.getTemplate() );
            seqt.addElement( CertificationRequest.getTemplate() );
        }

        @Override
        public boolean tagMatch(Tag tag) {
            return TAG.equals(tag);
        }

        @Override
        public ASN1Value decode(InputStream istream)
            throws InvalidBERException, IOException
        {
            return decode(TAG, istream);
        }

        @Override
        public ASN1Value decode(Tag implicitTag, InputStream istream)
            throws InvalidBERException, IOException
        {
            SEQUENCE seq = (SEQUENCE) seqt.decode(implicitTag, istream);

            assert(seq.size() == 2);

            return new TaggedCertificationRequest(
                            (INTEGER)      seq.elementAt(0),
                            (CertificationRequest)      seq.elementAt(1));
        }
    }
}
