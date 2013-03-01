/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss.pkix.cms;

import org.mozilla.jss.pkix.primitive.*;

import java.io.*;
import org.mozilla.jss.asn1.*;
import java.util.Vector;
import org.mozilla.jss.util.Assert;
import java.math.BigInteger;
import java.io.ByteArrayInputStream;

public class RecipientInfo implements ASN1Value {

    public static final Tag TAG = SEQUENCE.TAG;
    public Tag getTag() {
        return TAG;
    }

    private INTEGER               version;
    private IssuerAndSerialNumber issuerAndSerialNumber;
    private AlgorithmIdentifier   keyEncryptionAlgorithmID;
    private OCTET_STRING          encryptedKey;
    
    private SEQUENCE sequence = new SEQUENCE();

    public INTEGER getVersion() {
        return version;
    }
    public IssuerAndSerialNumber getissuerAndSerialNumber() {
        return issuerAndSerialNumber;
    }
    public AlgorithmIdentifier getKeyEncryptionAlgorithmID() {
        return keyEncryptionAlgorithmID;
    }
    public OCTET_STRING getEncryptedKey() {
        return encryptedKey;
    }


    private static final Template templateInstance = new Template();
    
    public static Template getTemplate() {
	return templateInstance;
    }


    private RecipientInfo() {
        }

    /**
     * Create a RecipientInfo ASN1 object.
     */

    public RecipientInfo(  INTEGER version,
			   IssuerAndSerialNumber issuerAndSerialNumber,
			   AlgorithmIdentifier keyEncryptionAlgorithmID,
			   OCTET_STRING encryptedKey) {

	Assert._assert(issuerAndSerialNumber != null);
	Assert._assert(keyEncryptionAlgorithmID != null);
	Assert._assert(encryptedKey != null);


        this.version = version;
        this.issuerAndSerialNumber = issuerAndSerialNumber;
        this.keyEncryptionAlgorithmID = keyEncryptionAlgorithmID;
        this.encryptedKey = encryptedKey;


        sequence.addElement(version);
        sequence.addElement(issuerAndSerialNumber);
        sequence.addElement(keyEncryptionAlgorithmID);
        sequence.addElement(encryptedKey);
        
    }

    public void encode(OutputStream ostream) throws IOException {
        encode(getTag(),ostream);
    }

    public void encode(Tag tag, OutputStream ostream) throws IOException {
        sequence.encode(tag,ostream);
    }


    /**
     * A template file for decoding a RecipientInfo blob
     *
     */

    public static class Template implements ASN1Template {
        public Tag getTag() {
            return RecipientInfo.TAG;
        }

        public boolean tagMatch(Tag tag) {
            return (tag.equals(RecipientInfo.TAG));
        }

        public ASN1Value decode(InputStream istream)
            throws IOException, InvalidBERException
            {
                return decode(getTag(),istream);
            }

        public ASN1Value decode(Tag implicitTag, InputStream istream)
            throws IOException, InvalidBERException
            {
                SEQUENCE.Template seqt = new SEQUENCE.Template();
                seqt.addElement(new INTEGER.Template());
                seqt.addElement(new IssuerAndSerialNumber.Template());
                seqt.addElement(new AlgorithmIdentifier.Template());
                seqt.addElement(new OCTET_STRING.Template());

                SEQUENCE seq = (SEQUENCE) seqt.decode(implicitTag,istream);
                Assert._assert(seq.size() ==4);

                return new RecipientInfo(
                    (INTEGER)               seq.elementAt(0),
                    (IssuerAndSerialNumber) seq.elementAt(1),
                    (AlgorithmIdentifier)   seq.elementAt(2),
                    (OCTET_STRING)          seq.elementAt(3)
                  
                    );
            }
    } // end of template

}
