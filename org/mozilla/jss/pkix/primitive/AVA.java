/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss.pkix.primitive;

import org.mozilla.jss.asn1.*;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.IOException;
import org.mozilla.jss.util.Assert;

/**
 * An AttributeValueAssertion, which has the following ASN.1
 *      definition (roughly):
 * <pre>
 *      AttributeValueAssertion ::= SEQUENCE {
 *          type        OBJECT IDENTIFIER,
 *          value       ANY DEFINED BY type }
 * </pre>
 */
public class AVA implements ASN1Value {

    private OBJECT_IDENTIFIER oid;
    private ANY value;

    public static final Tag TAG = SEQUENCE.TAG;
    public Tag getTag() {
        return TAG;
    }

    private AVA() { }

    public AVA(OBJECT_IDENTIFIER oid, ASN1Value value) {
        this.oid = oid;
        if( value instanceof ANY ) {
            this.value = (ANY) value;
        } else {
            byte[] encoded = ASN1Util.encode(value);
          try {
            this.value = (ANY) ASN1Util.decode(ANY.getTemplate(), encoded);
          } catch( InvalidBERException e ) {
            Assert.notReached("InvalidBERException while decoding as ANY");
          }
        }
    }

    public OBJECT_IDENTIFIER getOID() {
        return oid;
    }

    /**
     * Returns the value of this AVA, encoded as an ANY.
     */
    public ANY getValue() {
        return value;
    }

    public void encode(OutputStream ostream) throws IOException {
        encode(TAG, ostream);
    }

    public void encode(Tag implicit, OutputStream ostream)
        throws IOException
    {
        SEQUENCE seq = new SEQUENCE();
        seq.addElement(oid);
        seq.addElement(value);

        seq.encode(implicit, ostream);
    }

/**
 * A Template for decoding an AVA.
 */
public static class Template implements ASN1Template {

    public boolean tagMatch(Tag tag) {
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
        SEQUENCE.Template seqt = new SEQUENCE.Template();

        seqt.addElement( new OBJECT_IDENTIFIER.Template()   );
        seqt.addElement( new ANY.Template()                 );

        SEQUENCE seq = (SEQUENCE) seqt.decode(implicit, istream);

        // The template should have enforced this
        Assert._assert(seq.size() == 2);

        return new AVA( (OBJECT_IDENTIFIER) seq.elementAt(0),
                                            seq.elementAt(1) );
    }
}

}
