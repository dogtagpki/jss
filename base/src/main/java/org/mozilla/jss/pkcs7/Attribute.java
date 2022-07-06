/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss.pkcs7;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.mozilla.jss.asn1.ANY;
import org.mozilla.jss.asn1.ASN1Template;
import org.mozilla.jss.asn1.ASN1Value;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.asn1.SET;
import org.mozilla.jss.asn1.Tag;

/**
 * An Attribute, which has the following ASN.1
 *      definition (roughly):
 * <pre>
 *      Attribute ::= SEQUENCE {
 *          type        OBJECT IDENTIFIER,
 *          value       SET }
 * </pre>
 */
public class Attribute implements ASN1Value {

    private OBJECT_IDENTIFIER type;
    private SET values;

    public static final Tag TAG = SEQUENCE.TAG;
    @Override
    public Tag getTag() {
        return TAG;
    }

    public Attribute(OBJECT_IDENTIFIER type, SET values) {
        this.type = type;
        this.values = values;
    }

    public Attribute(OBJECT_IDENTIFIER type, ASN1Value value) {
        this.type = type;
        this.values = new SET();
        values.addElement(value);
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

    @Override
    public void encode(OutputStream ostream) throws IOException {
        encode(TAG, ostream);
    }

    @Override
    public void encode(Tag implicit, OutputStream ostream)
        throws IOException
    {
        SEQUENCE seq = new SEQUENCE();
        seq.addElement(type);
        seq.addElement(values);

        seq.encode(implicit, ostream);
    }

    public static Template getTemplate() {
        return templateInstance;
    }
    private static Template templateInstance = new Template();

/**
 * A Template for decoding an Attribute.
 */
public static class Template implements ASN1Template {

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
        SEQUENCE.Template seqt = new SEQUENCE.Template();

        seqt.addElement( new OBJECT_IDENTIFIER.Template()   );
        seqt.addElement( new SET.OF_Template(new ANY.Template()));

        SEQUENCE seq = (SEQUENCE) seqt.decode(implicit, istream);

        // The template should have enforced this
        assert(seq.size() == 2);

        return new Attribute( (OBJECT_IDENTIFIER) seq.elementAt(0),
                              (SET)               seq.elementAt(1));
    }
}

}
