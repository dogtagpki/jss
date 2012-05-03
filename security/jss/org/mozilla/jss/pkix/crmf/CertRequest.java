/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss.pkix.crmf;

import java.util.Date;
import org.mozilla.jss.asn1.*;
import org.mozilla.jss.util.Assert;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.IOException;
import org.mozilla.jss.pkix.primitive.*;

/**
 * A PKIX <i>CertRequest</i>.  Currently can only be decoded from its BER
 *  encoding. There are no methods for constructing one.
 */
public class CertRequest implements ASN1Value {

    private INTEGER certReqId;
    private CertTemplate certTemplate;
    private SEQUENCE controls; // may be null

    private CertRequest() { }

    /**
     * @param certReqId May NOT be null.
     * @param certTemplate May NOT be null.
     * @param controls May be null.
     */
    public CertRequest(INTEGER certReqId, CertTemplate certTemplate,
            SEQUENCE controls)
    {
        if( certReqId == null ) {
            throw new NullPointerException("certReqId is null");
        }
        this.certReqId = certReqId;
        if( certTemplate == null ) {
            throw new NullPointerException("certTemplate is null");
        }
        this.certTemplate = certTemplate;
        this.controls = controls;
    }

    /**
     * Returns the <i>certReqId</i> (certificate request ID) field.
     */
    public INTEGER getCertReqId() {
        return certReqId;
    }

    /**
     * Returns the <i>CertTemplate</i> field.
     */
    public CertTemplate getCertTemplate() {
        return certTemplate;
    }

    /**
     * Returns the number of optional Controls in the cert request.
     * The number may be zero.
     */
    public int numControls() {
        if(controls == null) {
            return 0;
        } else {
            return controls.size();
        }

    }

    /**
     * Returns the <i>i</i>th Control.  <code>i</code> must be in the
     * range [0..numControls-1].
     */
    public AVA controlAt(int i) {
        if( controls == null ) {
            throw new ArrayIndexOutOfBoundsException();
        }
        return (AVA) controls.elementAt(i);
    }

    ///////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////
    // DER-encoding
    ///////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////

    public static final Tag TAG = SEQUENCE.TAG;
    public Tag getTag() {
        return TAG;
    }

    /**
     * This method is not yet supported.
     */
    public void encode(OutputStream ostream) throws IOException {
        //Assert.notYetImplemented("CertRequest encoding");
        encode(getTag(),ostream);
    }

    /**
     * This method is not yet supported.
     */
    public void encode(Tag implicit, OutputStream ostream) throws IOException {
        //Assert.notYetImplemented("CertRequest encoding");
        SEQUENCE sequence = new SEQUENCE();

        sequence.addElement( certReqId );
        sequence.addElement( certTemplate );
		if (controls != null)
			sequence.addElement( controls );

        sequence.encode(implicit,ostream);
    }

    /**
     * A Template class for constructing <i>CertRequest</i>s from their
     * BER encoding.
     */
    public static class Template implements ASN1Template {
        private SEQUENCE.Template seqTemplate;

        public Template() {
            seqTemplate = new SEQUENCE.Template();
            seqTemplate.addElement( new INTEGER.Template() );
            seqTemplate.addElement( new CertTemplate.Template() );
            seqTemplate.addOptionalElement( new
                SEQUENCE.OF_Template( new AVA.Template() ));
        }

        public boolean tagMatch( Tag tag ) {
            return TAG.equals(tag);
        }

        public ASN1Value decode(InputStream istream)
            throws IOException, InvalidBERException
        {
            return decode(TAG, istream);
        }

        public ASN1Value decode(Tag implicit, InputStream istream)
            throws IOException, InvalidBERException
        {

            SEQUENCE seq = (SEQUENCE) seqTemplate.decode(implicit, istream);
            return new CertRequest(
                    (INTEGER) seq.elementAt(0),
                    (CertTemplate) seq.elementAt(1),
                    (SEQUENCE) seq.elementAt(2) );
        }
    }
}
