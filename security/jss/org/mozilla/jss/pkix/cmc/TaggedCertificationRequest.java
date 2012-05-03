/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkix.cmc;

import org.mozilla.jss.asn1.*;
import java.io.*;
import org.mozilla.jss.util.Assert;
import org.mozilla.jss.pkcs10.*;

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

    // no default constructor
    private TaggedCertificationRequest() { }

    /** 
     * Constructs a TaggedCertificationRequest from its components.
     *
     * @param bodyPartID the identifier.
     * @param certificationRequest the pkcs10 request.
     */
    public TaggedCertificationRequest(INTEGER bodyPartID, CertificationRequest certificationRequest) {
        sequence = new SEQUENCE();
        Assert._assert(bodyPartID.compareTo(BODYIDMAX) <= 0);
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

            return new TaggedCertificationRequest(
                            (INTEGER)      seq.elementAt(0),
                            (CertificationRequest)      seq.elementAt(1));
        }
    }
}
