/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkix.cms;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.mozilla.jss.asn1.ASN1Template;
import org.mozilla.jss.asn1.ASN1Value;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.OCTET_STRING;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.asn1.Tag;
import org.mozilla.jss.pkix.primitive.AlgorithmIdentifier;

public class DigestInfo implements ASN1Value {

    private AlgorithmIdentifier digestAlgorithm;
    private OCTET_STRING digest;
    private SEQUENCE sequence;

    public DigestInfo(AlgorithmIdentifier digestAlgorithm, OCTET_STRING digest){
        if( digestAlgorithm==null || digest==null ) {
            throw new IllegalArgumentException();
        }
        sequence = new SEQUENCE();
        this.digestAlgorithm = digestAlgorithm;
        sequence.addElement(digestAlgorithm);
        this.digest = digest;
        sequence.addElement(digest);
    }

    public AlgorithmIdentifier
    getDigestAlgorithm() {
        return digestAlgorithm;
    }

    public OCTET_STRING
    getDigest() {
        return digest;
    }

    private static final Tag TAG = SEQUENCE.TAG;
    @Override
    public Tag getTag() {
        return TAG;
    }

    @Override
    public boolean equals(Object obj) {
        if( obj==null || !(obj instanceof DigestInfo)) {
            return false;
        }
        DigestInfo di = (DigestInfo)obj;

        return byteArraysAreSame(di.digest.toByteArray(), digest.toByteArray());
    }

    /**
     * Compares two non-null byte arrays.  Returns true if they are identical,
     * false otherwise.
     */
    private static boolean byteArraysAreSame(byte[] left, byte[] right) {

        assert(left!=null && right!=null);

        if( left.length != right.length ) {
            return false;
        }

        for(int i = 0 ; i < left.length ; i++ ) {
            if( left[i] != right[i] ) {
                return false;
            }
        }

        return true;
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
     * A class for decoding the BER encoding of a DigestInfo.
     */
    public static class Template implements ASN1Template {

        private SEQUENCE.Template seqt;

        public Template() {
            seqt = new SEQUENCE.Template();
            seqt.addElement( AlgorithmIdentifier.getTemplate());
            seqt.addElement( OCTET_STRING.getTemplate() );
        }

        @Override
        public boolean tagMatch(Tag tag) {
            return TAG.equals(tag);
        }

        @Override
        public ASN1Value decode(InputStream ostream)
            throws InvalidBERException, IOException
        {
            return decode(TAG, ostream);
        }

        @Override
        public ASN1Value decode(Tag implicitTag, InputStream ostream)
            throws InvalidBERException, IOException
        {
            SEQUENCE seq = (SEQUENCE) seqt.decode(implicitTag, ostream);

            return new DigestInfo(
                    (AlgorithmIdentifier)       seq.elementAt(0),
                    (OCTET_STRING)              seq.elementAt(1) );
        }
    }
}
