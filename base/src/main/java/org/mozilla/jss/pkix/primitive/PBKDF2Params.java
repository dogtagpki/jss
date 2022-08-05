/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkix.primitive;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.mozilla.jss.asn1.ASN1Template;
import org.mozilla.jss.asn1.ASN1Value;
import org.mozilla.jss.asn1.CHOICE;
import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.OCTET_STRING;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.asn1.Tag;

/**
 * PKCS #5 <i>PBKDF2-Params</i>.
 */
public class PBKDF2Params implements ASN1Value {

    ///////////////////////////////////////////////////////////////////////
    // members and member access
    ///////////////////////////////////////////////////////////////////////
    private byte[] salt;
    private AlgorithmIdentifier otherSource;
    private int iterations;
    private int keyLength;
    private AlgorithmIdentifier prf;
    private SEQUENCE sequence;

    public byte[] getSalt() {
        return salt;
    }

    public int getIterations() {
        return iterations;
    }

    public AlgorithmIdentifier getOtherSource() {
        return otherSource;
    }

    public int getKeyLength() {
        return keyLength;
    }

    public AlgorithmIdentifier getPrf() {
        return prf;
    }

    ///////////////////////////////////////////////////////////////////////
    // constructors
    ///////////////////////////////////////////////////////////////////////

    /**
     * Creates a PBKDF2Params from a salt and iteration count
     */
    public PBKDF2Params(byte[] salt, AlgorithmIdentifier otherSource,
            int iterations, int keyLength, AlgorithmIdentifier prf) {
        this.salt = salt;
        this.otherSource = otherSource;
        this.iterations = iterations;
        this.keyLength = keyLength;
        this.prf = prf;
        sequence = new SEQUENCE();
        if(salt!=null) {
            sequence.addElement( new OCTET_STRING(salt) );
        }
        else {
            sequence.addElement(otherSource);
        }
        sequence.addElement( new INTEGER(iterations) );
        if(keyLength>0) {
            sequence.addElement(new INTEGER(keyLength));
        }
        sequence.addElement(prf);
    }

    /**
     * Creates a PBKDF2Params from a salt and iteration count
     */
    public PBKDF2Params(OCTET_STRING salt, AlgorithmIdentifier otherSource,
            INTEGER iterations, INTEGER keyLength, AlgorithmIdentifier prf) {
        this( salt.toByteArray(), otherSource, iterations.intValue(),
                keyLength != null ? keyLength.intValue() : 0, prf);
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
     * A template class for decoding a PBKDF2Params.
     */
    public static class Template implements ASN1Template {

        private SEQUENCE.Template seqt;

        public Template() {
            seqt = new SEQUENCE.Template();

            CHOICE.Template salt = CHOICE.getTemplate();
            salt.addElement(OCTET_STRING.getTemplate());
            salt.addElement(AlgorithmIdentifier.getTemplate());

            seqt.addElement(salt);
            seqt.addElement(INTEGER.getTemplate());
            seqt.addOptionalElement(INTEGER.getTemplate());
            seqt.addElement(AlgorithmIdentifier.getTemplate());
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
            OCTET_STRING specified = null;
            AlgorithmIdentifier otherSource = null;

            SEQUENCE seq = (SEQUENCE) seqt.decode(implicitTag, istream);

            CHOICE salt = (CHOICE) seq.elementAt(0);
            if (salt.getValue() instanceof OCTET_STRING saltValue) {
                specified = saltValue;
            }

            if (salt.getValue() instanceof AlgorithmIdentifier saltSource) {
                otherSource = saltSource;
            }

            return new PBKDF2Params( specified,
                                     otherSource,
                                     (INTEGER) seq.elementAt(1),
                                     (INTEGER) seq.elementAt(2),
                                     (AlgorithmIdentifier) seq.elementAt(3));
        }
    }
}
