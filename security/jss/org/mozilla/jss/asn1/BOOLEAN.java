/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss.asn1;

import java.io.OutputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * An ASN.1 <code>BOOLEAN</code> value.
 */
public class BOOLEAN implements ASN1Value {

    public static final Tag TAG = new Tag(Tag.Class.UNIVERSAL, 1);
    public static final Form FORM = Form.PRIMITIVE;

    public Tag getTag() {
        return TAG;
    }

    private ASN1Header getHeader() {
        return getHeader(TAG);
    }

    private ASN1Header getHeader(Tag implicitTag) {
        return new ASN1Header(implicitTag, FORM, 1 );
    }

    public void encode(OutputStream ostream) throws IOException {
        encode(TAG, ostream);
    }

    public void encode(Tag implicitTag, OutputStream ostream)
        throws IOException
    {
        getHeader(implicitTag).encode(ostream);
        if( val ) {
            ostream.write( 0xff );
        } else {
            ostream.write( 0x00 );
        }
    }

    private BOOLEAN() { }

    private boolean val;
    /**
     * Creates a <code>BOOLEAN</code> with the given value.
     */
    public BOOLEAN(boolean val) {
        this.val = val;
    }

    /**
     * Returns the boolean value of this <code>BOOLEAN</code>.
     */
    public boolean toBoolean() {
        return val;
    }

    /**
     * Returns "true" or "false".
     */
    public String toString() {
        if(val) {
            return "true";
        } else {
            return "false";
        }
    }

    private static final Template templateInstance = new Template();
    public static Template getTemplate() {
        return templateInstance;
    }

    /**
     * A Class for decoding <code>BOOLEAN</code> values from their BER
     * encodings.
     */
    public static class Template implements ASN1Template {
        public boolean tagMatch(Tag tag) {
            return( tag.equals( BOOLEAN.TAG ) );
        }

        public ASN1Value decode(InputStream istream)
            throws IOException, InvalidBERException
        {
            return decode(TAG, istream);
        }

        public ASN1Value decode(Tag tag, InputStream istream)
            throws IOException, InvalidBERException
        {
          try {
            ASN1Header head = new ASN1Header(istream);

            head.validate(tag, FORM);

            int b = istream.read();
            if( b == -1 ) {
                throw new InvalidBERException("End-of-file reached while "+
                    "decoding BOOLEAN");
            }

            if( b == 0x00 ) {
                return new BOOLEAN(false);
            } else {
                return new BOOLEAN(true);
            }

          } catch(InvalidBERException e) {
            throw new InvalidBERException(e, "BOOLEAN");
          }
        }
    }
}
