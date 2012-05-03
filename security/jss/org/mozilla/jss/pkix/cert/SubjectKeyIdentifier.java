/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkix.cert;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import org.mozilla.jss.asn1.*;
import org.mozilla.jss.util.Assert;

/**
 * Represent the Subject Key Identifier Extension.
 *
 * This extension, if present, provides a means of identifying the particular
 * public key used in an application.  This extension by default is marked
 * non-critical.
 *
 * <p>Extensions are additional attributes which can be inserted in a X509
 * v3 certificate. For example a "Driving License Certificate" could have
 * the driving license number as a extension.
 *
 * <p>Extensions are represented as a sequence of the extension identifier
 * (Object Identifier), a boolean flag stating whether the extension is to
 * be treated as being critical and the extension value itself (this is again
 * a DER encoding of the extension value).
 *
 * @author Michelle Zhao
 * @version 1.0
 * @see Extension
 */
public class SubjectKeyIdentifier extends Extension {

    ///////////////////////////////////////////////////////////////////////
    // Members
    ///////////////////////////////////////////////////////////////////////
    private OCTET_STRING keyIdentifier;
	private static OBJECT_IDENTIFIER OID = new
	OBJECT_IDENTIFIER("2.5.29.14");

    ///////////////////////////////////////////////////////////////////////
    // Construction
    ///////////////////////////////////////////////////////////////////////

    /** 
     * Constructs an SubjectKeyIdentifier from its components.
     *
     * @param keyIdentifier must not be null.
     */
    public SubjectKeyIdentifier(OCTET_STRING keyIdentifier) {
		super(OID,false,keyIdentifier);
    }

    public SubjectKeyIdentifier(boolean critical, OCTET_STRING keyIdentifier) {
		super(OID,critical,keyIdentifier);
    }

    public static class Template implements ASN1Template {

        private SEQUENCE.Template seqt;

        public Template() {
            seqt = new SEQUENCE.Template();
            seqt.addElement( OBJECT_IDENTIFIER.getTemplate() );
            seqt.addElement( BOOLEAN.getTemplate(), new BOOLEAN(false) );
            seqt.addElement( OCTET_STRING.getTemplate() );
        }

        public boolean tagMatch(Tag t) {
            return TAG.equals(t);
        }

        public ASN1Value decode(InputStream istream)
            throws IOException, InvalidBERException
        {
            return decode(TAG, istream);
        }

        public ASN1Value decode(Tag implicit, InputStream istream)
            throws IOException, InvalidBERException
        {
            SEQUENCE seq = (SEQUENCE) seqt.decode(implicit, istream);
            Assert._assert( ((OBJECT_IDENTIFIER) seq.elementAt(0)).equals(OID) );

            return new SubjectKeyIdentifier(
                ((BOOLEAN) seq.elementAt(1)).toBoolean(),
                (OCTET_STRING) seq.elementAt(2)
            );
        }
    }
}
