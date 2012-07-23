/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss.asn1;

import java.io.CharConversionException;

public class PrintableString extends CharacterString implements ASN1Value {

    public PrintableString(char[] chars) throws CharConversionException {
        super(chars);
    }

    public PrintableString(String s) throws CharConversionException {
        super(s);
    }

    CharConverter getCharConverter() {
        return new PrintableConverter();
    }

    public static final Tag TAG = new Tag( Tag.UNIVERSAL, 19 );
    public static final Form FORM = Form.PRIMITIVE;

    public Tag getTag() {
        return TAG;
    }

    /**
     * Returns a singleton instance of the decoding template for this class.
     */
    public static Template getTemplate() {
        return templateInstance;
    }
    private static final Template templateInstance = new Template();

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
        return new PrintableConverter();
    }

    protected CharacterString generateInstance(char[] chars)
        throws CharConversionException
    {
        return new PrintableString(chars);
    }

    protected String typeName() {
        return "PrintableString";
    }
}

private static class PrintableConverter implements CharConverter {

    private static boolean[] isPrintable = new boolean[128];
    static {
        char b;
        for(b='A'; b <= 'Z'; b++) {
            isPrintable[b] = true;
        }
        for(b='a'; b <= 'z'; b++) {
            isPrintable[b] = true;
        }
        for(b='0'; b <= '9'; b++) {
            isPrintable[b] = true;
        }
        isPrintable[' '] = true;
        isPrintable['\''] = true;
        isPrintable['('] = true;
        isPrintable[')'] = true;
        isPrintable['+'] = true;
        isPrintable[','] = true;
        isPrintable['-'] = true;
        isPrintable['.'] = true;
        isPrintable['/'] = true;
        isPrintable[':'] = true;
        isPrintable['='] = true;
        isPrintable['?'] = true;
    }

    public char[] byteToChar(byte[] bytes, int offset, int len)
        throws CharConversionException
    {
        char[] chars = new char[len];
        int c; // char index
        int b; // byte index
        for(c=0, b=offset; c < len; b++, c++) {
            if( (bytes[b] & 0x80) != 0 || !isPrintable[bytes[b]] ) {
				/* fix for bug 359010 - don't throw, just skip
				 * throw new CharConversionException(bytes[b]+ " is not "+
				 * "a valid character for a PrintableString");
				 */
            } else {
				chars[c] = (char) bytes[b];
			}
        }
        return chars;
    }

    public byte[] charToByte(char[] chars, int offset, int len)
        throws CharConversionException
    {
        byte[] bytes = new byte[len];
        int c; // char index
        int b; // byte index
        for(c=0, b=0; b < len; b++, c++) {
            if( (chars[c] & 0xff80) != 0 || !isPrintable[chars[c]] ) {
                throw new CharConversionException(chars[c]+ " is not "+
                    "a valid character for a PrintableString");
            }
            bytes[b] = (byte) (chars[c] & 0x7f);
        }
        return bytes;
    }
} // end of char converter

}
