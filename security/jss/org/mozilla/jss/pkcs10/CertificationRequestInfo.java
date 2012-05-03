/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss.pkcs10;

import org.mozilla.jss.asn1.*;
import org.mozilla.jss.pkix.primitive.*;
import org.mozilla.jss.util.*;
import java.security.cert.CertificateException;
import java.security.PublicKey;
import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;
import java.io.InputStream;
import java.io.PrintStream;
import java.io.OutputStream;
import java.io.IOException;

/**
 * A TBSCertificationRequest (to-be-signed CertificationRequest), 
 * the actual information in
 * a CertificationRequest apart from the signature.
 */
public class CertificationRequestInfo implements ASN1Value {


    private INTEGER version = new INTEGER(0);
    private Name subject;
    private SubjectPublicKeyInfo subjectPublicKeyInfo;
	private SET attributes;

    /**
     * Creates a CertificationRequestInfo with the required fields.
     */
    public CertificationRequestInfo(INTEGER version, Name subject,
									SubjectPublicKeyInfo
									subjectPublicKeyInfo, SET attributes)
    {
        setVersion(version);
        setSubject(subject);
        setSubjectPublicKeyInfo(subjectPublicKeyInfo);
        setAttributes(attributes);
    }

    public void setVersion(INTEGER version) {
        verifyNotNull(version);
        this.version = version;
    }
    public INTEGER getVersion() {
        return version;
    }

    public void setSubject(Name subject) {
        verifyNotNull(subject);
        this.subject = subject;
    }
    public Name getSubject() {
        return subject;
    }

    public void setSubjectPublicKeyInfo(
                    SubjectPublicKeyInfo subjectPublicKeyInfo)
    {
        verifyNotNull(subjectPublicKeyInfo);
        this.subjectPublicKeyInfo = subjectPublicKeyInfo;
    }
    /**
     * Extracts the SubjectPublicKeyInfo from the given public key and
     * stores it in the CertificationRequestInfo.
     *
     * @exception InvalidBERException If an error occurs decoding the
     *      the information extracted from the public key.
     */
    public void setSubjectPublicKeyInfo( PublicKey pubk ) 
        throws InvalidBERException, IOException
    {
        verifyNotNull(pubk);
        setSubjectPublicKeyInfo( new SubjectPublicKeyInfo(pubk) );
    }
    public SubjectPublicKeyInfo getSubjectPublicKeyInfo() {
        return subjectPublicKeyInfo;
    }

    public void setAttributes(SET attributes) {
        //verifyNotNull(attributes);
        this.attributes = attributes;
    }
    public SET getAttributes() {
        return attributes;
    }

    private void verifyNotNull(Object obj) {
        if( obj == null ) {
            throw new NullPointerException();
        }
    }

    static final Tag TAG = SEQUENCE.TAG;
    public Tag getTag() {
        return TAG;
    }

    public void encode(OutputStream ostream) throws IOException {
        encode(TAG, ostream);
    }

    public void encode(Tag implicitTag, OutputStream ostream)
        throws IOException
    {
        SEQUENCE seq = new SEQUENCE();

        seq.addElement(version );
        seq.addElement(subject);
        seq.addElement(subjectPublicKeyInfo);
        seq.addElement(new Tag(0), attributes);

        seq.encode(implicitTag, ostream);
    }

    private static final Template templateInstance = new Template();
    public static Template getTemplate() {
        return templateInstance;
    }

    public void print(PrintStream ps) throws IOException, InvalidBERException {
        ps.println("CertificationRequestInfo:");
        ps.println("Version: "+version);
        ps.println("Subject: "+subject.getRFC1485());
    }

    /**
     * Template class for decoding a CertificationRequestInfo.
     */
    public static class Template implements ASN1Template {

        SEQUENCE.Template seqt;

        public Template() {
            seqt = new SEQUENCE.Template();

            seqt.addElement(INTEGER.getTemplate()); //version
            seqt.addElement(Name.getTemplate()); //subject
            seqt.addElement(SubjectPublicKeyInfo.getTemplate());
            seqt.addElement(Tag.get(0), new SET.OF_Template(Attribute.getTemplate()));
        }

        public boolean tagMatch(Tag tag) {
            return TAG.equals(tag);
        }

        public ASN1Value decode(InputStream istream)
            throws InvalidBERException, IOException
        {
            return decode(TAG, istream);
        }

        public ASN1Value decode(Tag implicitTag, InputStream istream)
            throws InvalidBERException, IOException
        {
          try {
            SEQUENCE seq = (SEQUENCE) seqt.decode(implicitTag, istream);

            
            CertificationRequestInfo cinfo = new CertificationRequestInfo(
                    (INTEGER) seq.elementAt(0),     // version
                    (Name) seq.elementAt(1),        // subject
                    (SubjectPublicKeyInfo) seq.elementAt(2),
					(SET) seq.elementAt(3)
                );

            return cinfo;

          } catch( Exception e ) {
                throw new InvalidBERException(e.getMessage());
          }
        }
    }
}
