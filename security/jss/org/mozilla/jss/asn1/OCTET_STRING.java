/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss.asn1;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.IOException;
import java.io.ByteArrayOutputStream;

public class OCTET_STRING implements ASN1Value {

    public static final Tag TAG = new Tag(Tag.Class.UNIVERSAL, 4);
    public Tag getTag() {
        return TAG;
    }
    public static final Form FORM = Form.PRIMITIVE;

    byte[] data;

    private OCTET_STRING() { }

    public OCTET_STRING( byte[] data ) {
        this.data = data;
    }

    public byte[] toByteArray() {
        return data;
    }

    public void encode(OutputStream ostream) throws IOException {
        // use getTag() so we can be subclassed
        encode(getTag(), ostream);
    }

    public void encode(Tag implicitTag, OutputStream ostream)
        throws IOException
    {
        ASN1Header head = new ASN1Header(implicitTag, FORM, data.length);

        head.encode(ostream);

        ostream.write(data);
    }

    private static final Template templateInstance = new Template();
    public static Template getTemplate() {
        return templateInstance;
    }

public static class Template implements ASN1Template {

    public Tag getTag() {
        return TAG;
    }

    public boolean tagMatch(Tag tag) {
        return( TAG.equals(tag) );
    }

    public ASN1Value decode(InputStream istream)
        throws IOException, InvalidBERException
    {   
        return decode(getTag(), istream);
    }

    // this can be overridden by subclasses
    protected ASN1Value generateInstance(byte[] bytes) {
        return new OCTET_STRING( bytes );
    }

    // this can be overridden by subclasses
    protected String getName() {
        return "OCTET_STRING";
    }

    public ASN1Value decode(Tag implicitTag, InputStream istream)
        throws IOException, InvalidBERException
    {
      try {
        ASN1Header head = new ASN1Header(istream);

        head.validate(implicitTag);

        byte[] data;

        if( head.getContentLength() == -1 ) {
            // indefinite length encoding
            ASN1Header ahead;
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            do {
                ahead = ASN1Header.lookAhead( istream );
                if( ! ahead.isEOC() ) {
                    OCTET_STRING.Template ot = new OCTET_STRING.Template();
                    OCTET_STRING os = (OCTET_STRING) ot.decode(istream);
                    bos.write( os.toByteArray() );
                }
            } while( ! ahead.isEOC() );

            // consume EOC
            ahead = new ASN1Header(istream);

            data = bos.toByteArray();
        } else {
            data = new byte[ (int) head.getContentLength() ];
            ASN1Util.readFully(data, istream);
        }

        return generateInstance(data);

      } catch( InvalidBERException e ) {
        throw new InvalidBERException(e, getName());
      }
    }

} // end of Template

}
