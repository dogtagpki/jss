/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss.pkix.primitive;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.IOException;
import org.mozilla.jss.asn1.*;

/**
 * A RelativeDistinguishedName, whose ASN.1 is:
 * <pre>
 * RelativeDistinguishedName ::= SET SIZE(1..MAX) OF AttributeValueAssertion
 * </pre>
 */
public class RDN implements ASN1Value {

    private SET avas;

    private RDN() { }

    /**
     * An RDN must have at least one element at all times, so an initial
     *  element must be provided.
     */
    public RDN(AVA initialElement) {
        avas = new SET();
        avas.addElement(initialElement);
    }

    // This is for private use only, so we can be constructed from our
    // template.
    RDN(SET avas) {
        this.avas = avas;
    }

    public void add( AVA ava ) {
        avas.addElement( ava );
    }

    public AVA at( int idx ) {
        return (AVA) avas.elementAt( idx );
    }

    /**
     * @exception TooFewElementsException If removing this element would
     *  result in the RDN being empty.
     */
    public void removeAt( int idx ) throws TooFewElementsException {
        if( avas.size() <= 1 ) {
            throw new TooFewElementsException();
        }
        avas.removeElementAt( idx );
    }

    public int size() {
        return avas.size();
    }

    public static final Tag TAG = SET.TAG;
    public Tag getTag() {
        return TAG;
    }

    public void encode(OutputStream ostream) throws IOException {
        avas.encode(ostream);
    }

    public void encode(Tag implicit, OutputStream ostream)
        throws IOException
    {
        avas.encode(implicit, ostream);
    }

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
        AVA.Template avatemp = new AVA.Template();
        SET.OF_Template sett = new SET.OF_Template( avatemp );

        SET set =  (SET) sett.decode(implicit, istream);

        if(set.size() < 1) {
            throw new InvalidBERException("RDN with zero elements; "+
                "an RDN must have at least one element");
        }

        return new RDN(set);
    }
}

}
