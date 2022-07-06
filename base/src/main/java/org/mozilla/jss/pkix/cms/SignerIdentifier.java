/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkix.cms;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.mozilla.jss.asn1.ASN1Template;
import org.mozilla.jss.asn1.ASN1Value;
import org.mozilla.jss.asn1.CHOICE;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.OCTET_STRING;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.asn1.Tag;

/**
 * CMS <i>SignerIdentifier</i>:
 * <pre>
 * SignerIdentifier ::= CHOICE {
 *      issuerAndSerialNumber IssuerAndSerialNumber,
 *      subjectKeyIdentifier [0] SubjectKeyIdentifier }
 * </pre>
 */
public class SignerIdentifier implements ASN1Value {
    /**
     * The type of SignerIdentifier.
     */
    public static class Type {
        private Type() { }

        static Type ISSUER_AND_SERIALNUMBER = new Type();
        static Type SUBJECT_KEY_IDENTIFIER = new Type();
    }
    public static Type ISSUER_AND_SERIALNUMBER = Type.ISSUER_AND_SERIALNUMBER;
    public static Type SUBJECT_KEY_IDENTIFIER = Type.SUBJECT_KEY_IDENTIFIER;

    ///////////////////////////////////////////////////////////////////////
    // members and member access
    ///////////////////////////////////////////////////////////////////////

    private Type type;
    private IssuerAndSerialNumber issuerAndSerialNumber = null; // if type == ISSUER_AND_SERIALNUMBER
    private OCTET_STRING subjectKeyIdentifier = null; // if type == SUBJECT_KEY_IDENTIFIER

    /**
     * Returns the type of SignerIdentifier: <ul>
     * <li><code>ISSUER_AND_SERIALNUMBER</code>
     * <li><code>SUBJECT_KEY_IDENTIFIER</code>
     * </ul>
     */
    public Type getType() {
        return type;
    }

    /**
     * If type == ISSUER_AND_SERIALNUMBER, returns the IssuerAndSerialNumber
	 * field. Otherwise, returns null.
     */
    public IssuerAndSerialNumber getIssuerAndSerialNumber() {
        return issuerAndSerialNumber;
    }

    /**
     * If type == SUBJECT_KEY_IDENTIFIER, returns the SubjectKeyIdentifier
	 * field. Otherwise, returns null.
     */
    public OCTET_STRING getSubjectKeyIdentifier() {
        return subjectKeyIdentifier;
    }

    ///////////////////////////////////////////////////////////////////////
    // Constructors
    ///////////////////////////////////////////////////////////////////////

    public SignerIdentifier(Type type, IssuerAndSerialNumber
							 issuerAndSerialNumber,
							 OCTET_STRING subjectKeyIdentifier) {
        this.type = type;
        this.issuerAndSerialNumber = issuerAndSerialNumber;
        this.subjectKeyIdentifier = subjectKeyIdentifier;
    }

    /**
     * Creates a new SignerIdentifier with the given IssuerAndSerialNumber field.
     */
    public static SignerIdentifier
    createIssuerAndSerialNumber(IssuerAndSerialNumber ias) {
        return new SignerIdentifier( ISSUER_AND_SERIALNUMBER, ias, null );
    }

    /**
     * Creates a new SignerIdentifier with the given SubjectKeyIdentifier field.
     */
    public static SignerIdentifier
    createSubjectKeyIdentifier(OCTET_STRING ski) {
        return new SignerIdentifier(SUBJECT_KEY_IDENTIFIER , null, ski );
    }

    ///////////////////////////////////////////////////////////////////////
    // decoding/encoding
    ///////////////////////////////////////////////////////////////////////


    @Override
    public Tag getTag() {
        if( type == SUBJECT_KEY_IDENTIFIER ) {
            return Tag.get(0);
        } else {
            assert( type == ISSUER_AND_SERIALNUMBER );
            return IssuerAndSerialNumber.TAG;
        }
    }

    @Override
    public void encode(OutputStream ostream) throws IOException {

        if( type == SUBJECT_KEY_IDENTIFIER ) {
            // a CHOICE must be explicitly tagged
            //EXPLICIT e = new EXPLICIT( Tag.get(0), subjectKeyIdentifier );
            //e.encode(ostream);
            subjectKeyIdentifier.encode(Tag.get(0), ostream);
        } else {
            assert( type == ISSUER_AND_SERIALNUMBER );
            issuerAndSerialNumber.encode(ostream);
        }
    }

    @Override
    public void encode(Tag implicitTag, OutputStream ostream)
            throws IOException {
				//Assert.notReached("A CHOICE cannot be implicitly tagged");
        encode(ostream);
    }

    public static Template getTemplate() {
        return templateInstance;
    }
    private static Template templateInstance = new Template();

    /**
     * A Template for decoding a SignerIdentifier.
     */
    public static class Template implements ASN1Template {

        private CHOICE.Template choicet;

        public Template() {
            choicet = new CHOICE.Template();

            //EXPLICIT.Template et = new EXPLICIT.Template(
            //    Tag.get(0), OCTET_STRING.getTemplate() );
		    //choicet.addElement( et );
            choicet.addElement( Tag.get(0), OCTET_STRING.getTemplate() );
            choicet.addElement(IssuerAndSerialNumber.getTemplate() );
        }

        @Override
        public boolean tagMatch(Tag tag) {
            return choicet.tagMatch(tag);
        }

        @Override
        public ASN1Value decode(InputStream istream)
                throws InvalidBERException, IOException {
            CHOICE c = (CHOICE) choicet.decode(istream);

            if( c.getTag() == SEQUENCE.TAG ) {
                return createIssuerAndSerialNumber( (IssuerAndSerialNumber) c.getValue() );
            } else {
                assert( c.getTag().equals(Tag.get(0)) );
                //EXPLICIT e = (EXPLICIT) c.getValue();
				//ASN1Value dski =  e.getContent();
				//OCTET_STRING ski = (OCTET_STRING) e.getContent();
				OCTET_STRING ski = (OCTET_STRING) c.getValue();
				return createSubjectKeyIdentifier(ski);
            }
        }

        @Override
        public ASN1Value decode(Tag implicitTag, InputStream istream)
                throws InvalidBERException, IOException {
					//Assert.notReached("A CHOICE cannot be implicitly tagged");
            return decode(istream);
        }
    }
}





