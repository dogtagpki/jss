/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss.pkix.primitive;

import org.mozilla.jss.asn1.*;
import org.mozilla.jss.util.Assert;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.IOException;

public class AlgorithmIdentifier implements ASN1Value {

    private OBJECT_IDENTIFIER oid;
    private ASN1Value parameters=null;
    private SEQUENCE sequence = new SEQUENCE();

    public static final Tag TAG = SEQUENCE.TAG;
    public Tag getTag() {
        return TAG;
    }

    /**
     * Creates an <i>AlgorithmIdentifier</i> with no parameter.
     */
    public AlgorithmIdentifier(OBJECT_IDENTIFIER oid) {
        this.oid = oid;
        sequence.addElement( oid );
    }

    /**
     * Creates an <i>AlgorithmIdentifier</i>.
     * 
     * @param parameters The algorithm parameters. A value of <code>null</code>
     *      will be encoded with an ASN.1 <code>NULL</code>.
     */
    public AlgorithmIdentifier(OBJECT_IDENTIFIER oid, ASN1Value parameters) {
        this.oid = oid;
        sequence.addElement( oid );
        this.parameters = parameters;
        if( parameters != null ) {
            sequence.addElement(parameters);
        } else {
            sequence.addElement(new NULL());
        }
    }

    public OBJECT_IDENTIFIER getOID() {
        return oid;
    }

    /**
     * If this instance was constructed, returns the
     * parameter passed in to the constructor.  If this instance was
     * decoded from a template, returns an ANY that was read from the
     * BER stream. In either case, it will return null if no parameters
     * were supplied.
     */
    public ASN1Value getParameters() {
        return parameters;
    }

    private static final AlgorithmIdentifier.Template templateInstance =
                                new AlgorithmIdentifier.Template();
    public static AlgorithmIdentifier.Template getTemplate() {
        return templateInstance;
    }

    public void encode(OutputStream ostream) throws IOException {
        encode(TAG, ostream);
    }

    public void encode(Tag implicit, OutputStream ostream)
        throws IOException
    {
        sequence.encode(implicit, ostream);
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
        SEQUENCE.Template seqt = new SEQUENCE.Template();
        seqt.addElement( new OBJECT_IDENTIFIER.Template() );
        seqt.addOptionalElement( new ANY.Template() );

        SEQUENCE seq = (SEQUENCE) seqt.decode(implicit, istream);

        // the template should have enforced this
        Assert._assert( seq.size() == 2 );

        return new AlgorithmIdentifier(
            (OBJECT_IDENTIFIER)seq.elementAt(0),  // OID
            seq.elementAt(1)                      // parameters
        );
    }
} // end of Template

}
