/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkix.cmc;

import org.mozilla.jss.asn1.*;
import org.mozilla.jss.pkix.crmf.*;
import java.io.*;
import org.mozilla.jss.util.Assert;

/**
 * CMC <i>TaggedRequest</i>:
 * <pre>
 *   TaggedRequest ::= CHOICE { 
 *       tcr               [0] TaggedCertificationRequest, 
 *       crm               [1] CertReqMsg 
 *   } 
 * </pre>
 */
public class TaggedRequest implements ASN1Value {
    /**
     * The type of TaggedRequest.
     */
    public static class Type {
        private Type() { }

        static Type PKCS10 = new Type();
        static Type CRMF = new Type();
    }
    public static Type PKCS10 = Type.PKCS10;
    public static Type CRMF = Type.CRMF;

    ///////////////////////////////////////////////////////////////////////
    // members and member access
    ///////////////////////////////////////////////////////////////////////

    private Type type;
    private TaggedCertificationRequest tcr; // if type == PKCS10
    private CertReqMsg crm; // if type == CRMF

    ///////////////////////////////////////////////////////////////////////
    // Constructors
    ///////////////////////////////////////////////////////////////////////

    // no default constructor
    public TaggedRequest() { }

    /** 
     * Constructs a TaggedRequest from its components.
     *
     * @param type The type of the request.
     * @param tcr Tagged pkcs10 request.
     * @param crm CRMF request.
     */
    public TaggedRequest(Type type, TaggedCertificationRequest tcr, CertReqMsg crm) {
        this.type = type;
        this.tcr = tcr;
        this.crm = crm;
    }

    ///////////////////////////////////////////////////////////////////////
    // accessors
    ///////////////////////////////////////////////////////////////////////

    /**
     * Returns the type of TaggedRequest: <ul>
     * <li><code>PKCS10</code>
     * <li><code>CRMF</code>
     * </ul>
     */
    public Type getType() {
        return type;
    }

    /**
     * If type == PKCS10, returns the tcr field. Otherwise,
     * returns null.
     */
    public TaggedCertificationRequest getTcr() {
        return tcr;
    }

    /**
     * If type == CRMF, returns the crm field. Otherwise,
     * returns null.
     */
    public CertReqMsg getCrm() {
        return crm;
    }

    ///////////////////////////////////////////////////////////////////////
    // DER decoding/encoding
    ///////////////////////////////////////////////////////////////////////

    public Tag getTag() {
        if( type == PKCS10 ) {
            return Tag.get(0);
        } else {
            Assert._assert( type == CRMF );
            return Tag.get(1);
        }
    }

    public void encode(OutputStream ostream) throws IOException {

        if( type == PKCS10 ) {
            tcr.encode(Tag.get(0), ostream);
            // a CHOICE must be explicitly tagged
            //EXPLICIT e = new EXPLICIT( Tag.get(0), tcr );
            //e.encode(ostream);
        } else {
            Assert._assert( type == CRMF );
            crm.encode(Tag.get(1), ostream);
            // a CHOICE must be explicitly tagged
            //EXPLICIT e = new EXPLICIT( Tag.get(1), crm );
            //e.encode(ostream);
        }
    }

    public void encode(Tag implicitTag, OutputStream ostream)
            throws IOException {
				//Assert.notReached("A CHOICE cannot be implicitly tagged " +implicitTag.getNum());
				//tagAt() of SET.java actually returns the underlying type
			encode(ostream);
    }

    private static final Template templateInstance = new Template();
    public static Template getTemplate() {
        return templateInstance;
    }

    /**
     * A Template for decoding a ProofOfPossession.
     */
    public static class Template implements ASN1Template {

        private CHOICE.Template choicet;

        public Template() {
            choicet = new CHOICE.Template();

            //EXPLICIT.Template et = new EXPLICIT.Template(
            //    Tag.get(0), TaggedCertificationRequest.getTemplate() );
			//choicet.addElement( et );
            choicet.addElement( Tag.get(0), TaggedCertificationRequest.getTemplate() );
            //et = new EXPLICIT.Template(
            //    Tag.get(1), CertReqMsg.getTemplate() );
			//choicet.addElement( et );
            choicet.addElement( Tag.get(1), CertReqMsg.getTemplate() );
        }

        public boolean tagMatch(Tag tag) {
            return choicet.tagMatch(tag);
        }

        public ASN1Value decode(InputStream istream)
                throws InvalidBERException, IOException {
            CHOICE c = (CHOICE) choicet.decode(istream);

            if( c.getTag().equals(Tag.get(0)) ) {
                //EXPLICIT e = (EXPLICIT) c.getValue();
                //return new TaggedRequest(PKCS10,
				//						 (TaggedCertificationRequest)
				//						 e.getContent(), null );
                return new TaggedRequest(PKCS10, (TaggedCertificationRequest) c.getValue() , null);
            } else {
                Assert._assert( c.getTag().equals(Tag.get(1)) );
                //EXPLICIT e = (EXPLICIT) c.getValue();
                //return new TaggedRequest(CRMF, null,
				//						 (CertReqMsg) e.getContent() );
                return new TaggedRequest(CRMF, null, (CertReqMsg) c.getValue());
            }
        }

        public ASN1Value decode(Tag implicitTag, InputStream istream)
                throws InvalidBERException, IOException {
					//Assert.notReached("A CHOICE cannot be implicitly tagged");
				return decode(istream);
		}
	}
}



