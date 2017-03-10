/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkix.primitive;

import org.mozilla.jss.asn1.*;
import org.mozilla.jss.util.Assert;
import java.io.CharConversionException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * An X.500 <i>DirectoryString</i>.
 * DirectoryString is defined as follows:
 * <pre>
 * DirectoryString ::= CHOICE {
 *      teletexString               TeletexString (SIZE (1..MAX)),
 *      printableString             PrintableString (SIZE (1..MAX)),
 *      universalString             UniversalString (SIZE (1..MAX)),
 *      utf8String                  UTF8String (SIZE (1..MAX)),
 *      bmpString                   BMPString (SIZE (1..MAX))  }
 * </pre>
 */
public class DirectoryString implements ASN1Value {

    private DirectoryString() { }

    private CharacterString asn1String;

    /**
     * Encodes a Java String into a Directory String.
     * The following rules for choosing an encoding are from the
     *  <a href="http://www.ietf.org/html.charters/pkix-charter.html">IETF
     *  PKIX</a> document <i>Internet X.509 Public Key Infrastructure:
     *  Certificate and CRL Profile</i>: <ul>
     * <li> The preferred encoding is UTF8String, and all certificates
     *      issued after December 31, 2003, MUST use UTF8String encoding,
     *      with a few exceptions.
     * <li>Until December 31, 2003, strings that fit in the PrintableString
     *      character set MAY use PrintableString.
     * <li>Until December 31, 2003, string that fit in the BMPString character
     *      set MAY use BMPString.
     * <li>Strings that fit in neither the PrintableString nor the BMPString
     *      character set MUST use UTF8String.
     * </ul>
     * This is all very nice, but for backwards compatibility, what we really
     * do is: <ul>
     * <li>Try PrintableString
     * <li>Try TeletexString
     * <li>Try UniversalString
     * </ul>
     */
    public DirectoryString(String s) throws CharConversionException {
        try {
            try {
                asn1String = new PrintableString(s);
            } catch( CharConversionException e ) {
                asn1String = new TeletexString(s);
            }
        } catch( CharConversionException e ) {
            asn1String = new UniversalString(s);
        }
    }

    /**
     * Creates a DirectoryString from an ASN.1 string.
     * @param s Must be a TeletexString, PrintableString, UniversalString,
     *      UTF8String, or BMPString.
     */
    public DirectoryString(CharacterString s) {
        if( !(s instanceof PrintableString ) && !(s instanceof BMPString) &&
            !(s instanceof UTF8String) && !(s instanceof TeletexString) &&
            !(s instanceof UniversalString) )
        {
            throw new IllegalArgumentException("DirectoryString must be "+
                "TeletexString, PrintableString, UniversalString, UTF8STring,"+
                " or BMPString");
        }
        asn1String = s;
    }

    /**
     * Converts an ASN.1 DirectoryString to a Java string.
     */
    public String toString() {
        return asn1String.toString();
    }

    public Tag getTag() {
        return asn1String.getTag();
    }

    public void encode(OutputStream ostream) throws IOException {
        asn1String.encode(ostream);
    }

    public void encode(Tag implicitTag, OutputStream ostream)
        throws IOException
    {
        asn1String.encode(implicitTag, ostream);
    }

    /**
     * Returns a singleton instance of the decoding template for this class.
     */
    public static Template getTemplate() {
        return templateInstance;
    }
    private static final Template templateInstance = new Template();

    /**
     * A Template for decoding DirectoryStrings from their BER encoding.
     */
    public static class Template implements ASN1Template {
        private CHOICE.Template choicet;

        public Template() {
            choicet = new CHOICE.Template();
            choicet.addElement( PrintableString.getTemplate() );
            choicet.addElement( BMPString.getTemplate() );
            choicet.addElement( UTF8String.getTemplate() );
            choicet.addElement( TeletexString.getTemplate() );
            choicet.addElement( UniversalString.getTemplate() );
        }

        public boolean tagMatch(Tag tag) {
            return choicet.tagMatch(tag);
        }

        public ASN1Value decode(InputStream istream)
            throws IOException, InvalidBERException
        {
            CHOICE choice = (CHOICE) choicet.decode(istream);

            return new DirectoryString( (CharacterString) choice.getValue());
        }

        /**
         * @param implicitTag <b>This parameter is ignored</b>, because
         *      DirectoryStrings (being CHOICEs) cannot have implicit tags.
         * @exception InvalidBERException If the encoding does not contain a
         *      valid DirectoryString.
         */
        public ASN1Value decode(Tag implicitTag, InputStream istream)
            throws IOException, InvalidBERException
        {
            Assert._assert( tagMatch(implicitTag) );
            return decode(istream);
        }
    }
}
