/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss.asn1;

import java.io.CharConversionException;
import java.io.UnsupportedEncodingException;
import org.mozilla.jss.util.Assert;

public class UTF8String extends CharacterString implements ASN1Value {

    public UTF8String(char[] chars) throws CharConversionException {
        super(chars);
    }

    public UTF8String(String s) throws CharConversionException {
        super(s);
    }

    CharConverter getCharConverter() {
        return new UTF8Converter();
    }

    public static final Tag TAG = new Tag( Tag.UNIVERSAL, 12 );
    public static final Form FORM = Form.PRIMITIVE;

    public Tag getTag() {
        return TAG;
    }

    private static final Template templateInstance = new Template();
    /**
     * Returns a singleton instance of UTF8String.Template. This is more
     * efficient than creating a new UTF8String.Template.
     */
    public static Template getTemplate() {
        return templateInstance;
    }

// nested class
public static class Template
    extends CharacterString.Template implements ASN1Template
{
    protected Tag getTag() {
        return TAG;
    }

    public boolean tagMatch(Tag tag) {
        return TAG.equals(tag);
    }

    protected CharConverter getCharConverter() {
        return new UTF8Converter();
    }

    protected CharacterString generateInstance(char[] chars)
        throws CharConversionException
    {
        return new UTF8String(chars);
    }

    protected String typeName() {
        return "UTF8String";
    }
}

private static class UTF8Converter implements CharConverter {

    public char[] byteToChar(byte[] bytes, int offset, int len)
        throws CharConversionException
    {
        try {

            String s = new String(bytes, offset, len, "UTF8");
            return s.toCharArray();

        } catch( UnsupportedEncodingException e ) {
            String err = "Unable to find UTF8 encoding mechanism";
            Assert.notReached(err);
            throw new CharConversionException(err);
        }
    }

    public byte[] charToByte(char[] chars, int offset, int len)
        throws CharConversionException
    {
        try {

            String s = new String(chars, offset, len);
            return s.getBytes("UTF8");

        } catch( UnsupportedEncodingException e ) {
            String err = "Unable to find UTF8 encoding mechanism";
            Assert.notReached(err);
            throw new CharConversionException(err);
        }
    }
} // end of char converter

}
