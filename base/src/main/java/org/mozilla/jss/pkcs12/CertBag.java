/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkcs12;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.mozilla.jss.asn1.ANY;
import org.mozilla.jss.asn1.ASN1Template;
import org.mozilla.jss.asn1.ASN1Util;
import org.mozilla.jss.asn1.ASN1Value;
import org.mozilla.jss.asn1.EXPLICIT;
import org.mozilla.jss.asn1.IA5String;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;
import org.mozilla.jss.asn1.OCTET_STRING;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.asn1.Tag;

/**
 * A PKCS #12 cert bag.
 */
public class CertBag implements ASN1Value {


    ///////////////////////////////////////////////////////////////////////
    // Cert Type OIDs
    ///////////////////////////////////////////////////////////////////////
    private static final OBJECT_IDENTIFIER CERT_TYPES =
        OBJECT_IDENTIFIER.PKCS9.subBranch(22);

    public static final OBJECT_IDENTIFIER X509_CERT_TYPE =
        CERT_TYPES.subBranch(1);

    public static final OBJECT_IDENTIFIER SDSI_CERT_TYPE =
        CERT_TYPES.subBranch(2);

    ///////////////////////////////////////////////////////////////////////
    // members and member access
    ///////////////////////////////////////////////////////////////////////
    private OBJECT_IDENTIFIER certType;
    private ANY cert;
    private SEQUENCE sequence;

    /**
     * Returns the certType field of the CertBag. Currently defined types are:
     * <ul>
     * <li><i>X509Certificate</i> (<code>X509_CERT_TYPE</code>)
     * <li><i>SDSICertificate</i> (<code>SDSI_CERT_TYPE</code>)
     * </ul>
     */
    public OBJECT_IDENTIFIER getCertType() {
        return certType;
    }

    /**
     * Returns the cert field of the CertBag.
     */
    public ANY getCert() {
        return cert;
    }

    /**
     * Returns the cert field of the CertBag based on its type.
     * <ul>
     * <li>If the type is <code>X509_CERT_TYPE</code>, returns
     *      and OCTET_STRING which is the DER-encoding of an X.509 certificate.
     * <li>If the type is <code>SDSI_CERT_TYPE</code>, returns
     *      an IA5String.
     * <li>For all other types, returns an ANY.
     * </ul>
     *
     * @exception InvalidBERException If the cert is not encoded correctly.
     */
    public ASN1Value getInterpretedCert() throws InvalidBERException {
        if( certType.equals(X509_CERT_TYPE) ) {
            return cert.decodeWith(OCTET_STRING.getTemplate());
        } else if( certType.equals(SDSI_CERT_TYPE) ) {
            return cert.decodeWith(IA5String.getTemplate());
        } else {
            return cert;
        }
    }


    ///////////////////////////////////////////////////////////////////////
    // constructors
    ///////////////////////////////////////////////////////////////////////

    /**
     * Creates a CertBag from a type and a cert.
     */
    public CertBag(OBJECT_IDENTIFIER certType, ASN1Value cert) {
        if( certType==null || cert==null ) {
            throw new IllegalArgumentException("certType or cert is null");
        }
        this.certType = certType;
        if( cert instanceof ANY ) {
            this.cert = (ANY) cert;
        } else {
          try {
            byte[] encoded = ASN1Util.encode(cert);
            this.cert = (ANY) ASN1Util.decode( ANY.getTemplate(), encoded);
          } catch(InvalidBERException e) {
            throw new RuntimeException("Unable to convert ASN1Value to ANY: "+ e.getMessage(), e);
          }
        }
        sequence = new SEQUENCE();
        sequence.addElement(this.certType);
        sequence.addElement(new EXPLICIT(new Tag(0), this.cert) );
    }

    ///////////////////////////////////////////////////////////////////////
    // DER encoding
    ///////////////////////////////////////////////////////////////////////
    private static final Tag TAG = SEQUENCE.TAG;

    @Override
    public Tag getTag() {
        return TAG;
    }

    @Override
    public void encode(OutputStream ostream) throws IOException {
        sequence.encode(ostream);
    }

    @Override
    public void encode(Tag implicitTag, OutputStream ostream)
        throws IOException
    {
        sequence.encode(implicitTag, ostream);
    }

    private static final Template templateInstance = new Template();
    public static Template getTemplate() {
        return templateInstance;
    }

    /**
     * A Template class for decoding CertBags from their BER encoding.
     */
    public static class Template implements ASN1Template {

        private SEQUENCE.Template seqt;

        public Template() {
            seqt = new SEQUENCE.Template();
            seqt.addElement( OBJECT_IDENTIFIER.getTemplate() );
            seqt.addElement( new EXPLICIT.Template(
                                    new Tag(0),
                                    ANY.getTemplate() ) );
        }

        @Override
        public boolean tagMatch(Tag tag) {
            return TAG.equals(tag);
        }

        @Override
        public ASN1Value decode(InputStream istream)
            throws InvalidBERException, IOException
        {
            return decode(TAG, istream);
        }

        @Override
        public ASN1Value decode(Tag implicitTag, InputStream istream)
            throws InvalidBERException, IOException
        {
            SEQUENCE seq = (SEQUENCE) seqt.decode(implicitTag, istream);

            return new CertBag( (OBJECT_IDENTIFIER) seq.elementAt(0),
                                ((EXPLICIT)seq.elementAt(1)).getContent() );
        }
    }
}
