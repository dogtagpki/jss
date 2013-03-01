/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss.asn1;

import java.io.IOException;
import java.io.InputStream;

/**
 * Represents an ASN.1 <code>ENUMERATED</code> value. This has the same
 * interface as <code>INTEGER</code>
 */
public class ENUMERATED extends INTEGER implements ASN1Value {

    public static final Tag TAG = new Tag(Tag.Class.UNIVERSAL, 10);
    public Tag getTag() {
        return TAG;
    }

    /**
     * Creates a new ENUMERATED value from a long.
     */
    public ENUMERATED( long val ) {
        super( val );
    }

    ENUMERATED( byte[] valBytes ) {
        super( valBytes );
    }

    /**
     * Returns the value as a long.
     */
    public long getValue() {
        return longValue();
    }

    private static final ENUMERATED.Template templateInstance =
                                            new ENUMERATED.Template();
    public static ASN1Template getTemplate() {
        return templateInstance;
    }


/**
 * A template for decoding ENUMERATED values from their BER encodings.
 * The template reads the value as an INTEGER.  It does not check that it
 * is a valid value for the ENUMERATED type.
 */
public static class Template
    extends INTEGER.Template implements ASN1Template
{
    Tag getTag() {
        return ENUMERATED.TAG;
    }
    public boolean tagMatch(Tag tag) {
        return( tag.equals(ENUMERATED.TAG) );
    }

    public ASN1Value
    decode(Tag tag, InputStream derStream)
        throws InvalidBERException, IOException
    {
      try {
        ASN1Header wrapper = new ASN1Header(derStream);

        wrapper.validate(tag, FORM);

        // Is length < 1 ?
        if( wrapper.getContentLength() < 1 ) {
            throw new InvalidBERException("Invalid 0 length for ENUMERATED");
        }

        byte[] valBytes = new byte[ (int) wrapper.getContentLength() ];
        ASN1Util.readFully(valBytes, derStream);
        return new ENUMERATED( valBytes );

      } catch(InvalidBERException e) {
        throw new InvalidBERException(e, "ENUMERATED");
      }
    }

} // end of Template

}
