/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkix.primitive;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.mozilla.jss.asn1.ASN1Template;
import org.mozilla.jss.asn1.ASN1Value;
import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.OCTET_STRING;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.asn1.Tag;

/**
 * PKCS #5 <i>PBEParameter</i>, and PKCS #12 <i>pkcs-12PbeParams</i>. The only
 * difference between the two is that PKCS #5 dictates that the size of the
 * salt must be 8 bytes, while PKCS #12 leaves the salt length undefined.
 * To work with both standards, this class does not check the length of the
 * salt but rather leaves that to the application.
 */
public class PBEParameter implements ASN1Value {

    ///////////////////////////////////////////////////////////////////////
    // members and member access
    ///////////////////////////////////////////////////////////////////////
    private byte[] salt;
    private int iterations;
    private SEQUENCE sequence;

    public byte[] getSalt() {
        return salt;
    }

    public int getIterations() {
        return iterations;
    }

    ///////////////////////////////////////////////////////////////////////
    // constructors
    ///////////////////////////////////////////////////////////////////////

    /**
     * Creates a PBEParameter from a salt and iteration count. Neither
     * may be null.
     */
    public PBEParameter(byte[] salt, int iterations) {
        this.salt = salt;
        this.iterations = iterations;
        sequence = new SEQUENCE();
        sequence.addElement( new OCTET_STRING(salt) );
        sequence.addElement( new INTEGER(iterations) );
    }

    /**
     * Creates a PBEParameter from a salt and iteration count. Neither
     * may be null.
     */
    public PBEParameter(OCTET_STRING salt, INTEGER iterations) {
        this( salt.toByteArray(), iterations.intValue() );
    }

    ///////////////////////////////////////////////////////////////////////
    // DER encoding
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
        throws IOException
    {
        sequence.encode(implicitTag, ostream);
    }


    private static final Template templateInstance = new Template();
    public static Template getTemplate() {
        return templateInstance;
    }

    /**
     * A template class for decoding a PBEParameter.
     */
    public static class Template implements ASN1Template {

        private SEQUENCE.Template seqt;

        public Template() {
            seqt = new SEQUENCE.Template();
            seqt.addElement( OCTET_STRING.getTemplate() );
            seqt.addElement( INTEGER.getTemplate() );
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

            return new PBEParameter( (OCTET_STRING) seq.elementAt(0),
                                     (INTEGER)      seq.elementAt(1) );
        }
    }
}
