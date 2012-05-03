/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss.asn1;

import java.io.OutputStream;
import java.io.InputStream;
import java.io.IOException;

public class NULL implements ASN1Value {

    public static final Tag TAG = new Tag(Tag.Class.UNIVERSAL, 5);
    public Tag getTag() {
        return TAG;
    }
    public static final Form FORM = Form.PRIMITIVE;

    public void encode(OutputStream ostream) throws IOException {
        encode(TAG, ostream);
    }

    public void encode(Tag implicitTag, OutputStream ostream)
        throws IOException
    {
        ASN1Header head = new ASN1Header(implicitTag, FORM, 0);
        head.encode(ostream);
    }

    private static final NULL instance = new NULL();
    public static NULL getInstance() {
        return instance;
    }

    private static final Template templateInstance = new Template();
    public static Template getTemplate() {
        return templateInstance;
    }

public static class Template implements ASN1Template {

    public Tag getTag() {
        return NULL.TAG;
    }
    public boolean tagMatch(Tag tag) {
        return( tag.equals(NULL.TAG) );
    }

    public ASN1Value decode(InputStream istream)
        throws IOException, InvalidBERException
    {
        return decode(getTag(), istream);
    }

    public ASN1Value decode(Tag implicitTag, InputStream istream)
        throws IOException, InvalidBERException
    {
      try {
        ASN1Header head = new ASN1Header(istream);

        head.validate(implicitTag, FORM);
        if( head.getContentLength() != 0 ) {
            throw new InvalidBERException("Invalid length ("+
                head.getContentLength()+") for NULL; only 0 is permitted");
        }

        return new NULL();

      } catch(InvalidBERException e) {
        throw new InvalidBERException(e, "NULL");
      }
    }
} // end of Template

}
