/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */


package org.mozilla.jss.pkix.cmc;

import org.mozilla.jss.util.Assert;
import org.mozilla.jss.asn1.*;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.BitSet;

/**
 * CMC <i>LraPopWitness</i>:
 * <pre>
 *      LraPopWitness::= SEQUENCE { 
 *          pkiDataBodyid       BodyPartID
 *          bodyids             SEQUENCE SIZE (1..MAX) OF BodyPartID, 
 *     } 
 * </pre>
 */
public class LraPopWitness implements ASN1Value {
    public static final INTEGER BODYIDMAX = new INTEGER("4294967295");

    ///////////////////////////////////////////////////////////////////////
    // Members
    ///////////////////////////////////////////////////////////////////////
    private INTEGER pkiDataBodyid;
    private SEQUENCE bodyIds; 
    private SEQUENCE sequence;

    ///////////////////////////////////////////////////////////////////////
    // Constructors
    ///////////////////////////////////////////////////////////////////////

    private LraPopWitness() { }

    /**
     * @param pkiDataBodyid A PKI data BodyPartID. 
     * @param bodyIds The sequence of bodyPartIDs.
     */
    public LraPopWitness(INTEGER pkiDataBodyid, SEQUENCE bodyIds) {
        if (pkiDataBodyid == null || bodyIds == null) 
            throw new IllegalArgumentException(
               "parameter to LraPopWitness constructor is null");
        sequence = new SEQUENCE();
        this.pkiDataBodyid = pkiDataBodyid;
        sequence.addElement(pkiDataBodyid);
        this.bodyIds = bodyIds;
        sequence.addElement(bodyIds);
    }

    /**
     * Adds a BodyPartID to the bodyIds SEQUENCE.
     */
    public void addBodyPartId(int id) {
        INTEGER id1 = new INTEGER(id);
        Assert._assert(id1.compareTo(BODYIDMAX) <= 0);
        bodyIds.addElement( id1 );
    }

    ///////////////////////////////////////////////////////////////////////
    // member access
    ///////////////////////////////////////////////////////////////////////
    public INTEGER getPKIDataBodyid() {
        return pkiDataBodyid;
    }

    public SEQUENCE getBodyIds() {
        return bodyIds;
    }
    ///////////////////////////////////////////////////////////////////////
    // decoding/encoding
    ///////////////////////////////////////////////////////////////////////

    public static final Tag TAG = SEQUENCE.TAG;
    public Tag getTag() {
        return TAG;
    }

    public void encode(OutputStream ostream) throws IOException {
        sequence.encode(TAG, ostream);
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


    public static class Template implements ASN1Template {

        private SEQUENCE.Template seqt;

        public Template() {
            seqt = new SEQUENCE.Template();
            seqt.addElement( INTEGER.getTemplate() );
            seqt.addElement( new SEQUENCE.OF_Template(INTEGER.getTemplate()) );
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

            return new LraPopWitness((INTEGER)seq.elementAt(0),
                                     (SEQUENCE)seq.elementAt(1));
        }
    }
}
