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
import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.asn1.SET;
import org.mozilla.jss.asn1.Tag;

/**
 * A tagged attribute, which has the following ASN.1
 *      definition :
 * <pre>
 *   TaggedAttribute ::= SEQUENCE {
 *      bodyPartID         BodyPartId,
 *      attrType           OBJECT IDENTIFIER,
 *      attrValues         SET OF AttributeValue
 *   bodyIdMax INTEGER ::= 4294967295
 *
 *   BodyPartID ::= INTEGER(0..bodyIdMax)
 * </pre>
 */
public class TaggedAttribute implements ASN1Value {
	public static final INTEGER BODYIDMAX = new INTEGER("4294967295");

    ///////////////////////////////////////////////////////////////////////
    // Members
    ///////////////////////////////////////////////////////////////////////

    private SEQUENCE sequence;
    private INTEGER bodyPartID;
    private OBJECT_IDENTIFIER type;
    private SET values;

    ///////////////////////////////////////////////////////////////////////
    // Construction
    ///////////////////////////////////////////////////////////////////////

    public TaggedAttribute(INTEGER bodyPartID, OBJECT_IDENTIFIER type, SET values) {
        sequence = new SEQUENCE();
        assert(bodyPartID.compareTo(BODYIDMAX) <= 0);
        this.bodyPartID = bodyPartID;
        sequence.addElement(bodyPartID);
        this.type = type;
        sequence.addElement(type);
        this.values = values;
        sequence.addElement(values);
    }

    public TaggedAttribute(INTEGER bodyPartID, OBJECT_IDENTIFIER type, ASN1Value value) {
        sequence = new SEQUENCE();
        assert(bodyPartID.compareTo(BODYIDMAX) <= 0);
        this.bodyPartID = bodyPartID;
        sequence.addElement(bodyPartID);
        this.type = type;
        sequence.addElement(type);
        this.values = new SET();
        values.addElement(value);
        sequence.addElement(values);
    }

    ///////////////////////////////////////////////////////////////////////
    // accessors
    ///////////////////////////////////////////////////////////////////////

    public INTEGER getBodyPartID() {
        return bodyPartID;
    }

    public OBJECT_IDENTIFIER getType() {
        return type;
    }

    /**
     * If this AVA was constructed, returns the SET of ASN1Values passed to the
     * constructor.  If this Attribute was decoded with an Attribute.Template,
     * returns a SET of ANYs.
     */
    public SET getValues() {
        return values;
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
    public void encode(Tag implicit, OutputStream ostream)
        throws IOException
    {
        sequence.encode(implicit, ostream);
    }

    public static Template getTemplate() {
        return templateInstance;
    }
    private static Template templateInstance = new Template();

	/**
	 * A Template for decoding an Attribute.
	 */
	public static class Template implements ASN1Template {
        private SEQUENCE.Template seqt;

        public Template() {
            seqt = new SEQUENCE.Template();
            seqt.addElement( INTEGER.getTemplate() );
			seqt.addElement( new OBJECT_IDENTIFIER.Template()   );
			seqt.addElement( new SET.OF_Template(new ANY.Template()));
        }


		@Override
        public boolean tagMatch(Tag tag) {
			return TAG.equals(tag);
		}

		@Override
        public ASN1Value decode(InputStream istream)
			 throws IOException, InvalidBERException
		{
			return decode(TAG, istream);
		}

		@Override
        public ASN1Value decode(Tag implicit, InputStream istream)
			 throws IOException, InvalidBERException
		{
			SEQUENCE seq = (SEQUENCE) seqt.decode(implicit, istream);

			// The template should have enforced this
			assert(seq.size() == 3);

			return new TaggedAttribute(
                            (INTEGER)      seq.elementAt(0),
							(OBJECT_IDENTIFIER) seq.elementAt(1),
                            (SET)               seq.elementAt(2));
		}
	}
}



