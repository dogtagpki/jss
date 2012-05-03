/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkcs7;

import org.mozilla.jss.asn1.*;
import org.mozilla.jss.pkix.primitive.*;
import java.io.*;

public class DigestedData implements ASN1Value {

    ///////////////////////////////////////////////////////////////////////
    // members and member access
    ///////////////////////////////////////////////////////////////////////
    private INTEGER version;
    private AlgorithmIdentifier digestAlgorithm;
    private ContentInfo contentInfo;
    private OCTET_STRING digest;
    private SEQUENCE sequence;  // for DER encoding

    public INTEGER getVersion() {
        return version;
    }

    public AlgorithmIdentifier getDigestAlgorithm() {
        return digestAlgorithm;
    }

    public ContentInfo getContentInfo() {
        return contentInfo;
    }

    public OCTET_STRING getDigest() {
        return digest;
    }

    ///////////////////////////////////////////////////////////////////////
    // constructors
    ///////////////////////////////////////////////////////////////////////
    private DigestedData() { }

    public DigestedData(INTEGER version, AlgorithmIdentifier digestAlgorithm,
                ContentInfo contentInfo, OCTET_STRING digest)
    {
        if( version==null || digestAlgorithm==null || contentInfo==null ||
                digest==null ) {
            throw new IllegalArgumentException("DigestedData constructor"
                +" parameter is null");
        }

        this.version = version;
        this.digestAlgorithm = digestAlgorithm;
        this.contentInfo = contentInfo;
        this.digest = digest;

        sequence = new SEQUENCE();
        sequence.addElement(version);
        sequence.addElement(digestAlgorithm);
        sequence.addElement(contentInfo);
        sequence.addElement(digest);
    }

    ///////////////////////////////////////////////////////////////////////
    // DER encoding
    ///////////////////////////////////////////////////////////////////////

    private static final Tag TAG = SEQUENCE.TAG;

    public Tag getTag() {
        return TAG;
    }

    public void encode(OutputStream ostream) throws IOException {
        sequence.encode(ostream);
    }

    public void encode(Tag implicitTag, OutputStream ostream)
            throws IOException {
        sequence.encode(implicitTag, ostream);
    }

    /**
     * A Template for decoding BER-encoded DigestData items.
     */
    public static class Template implements ASN1Template {

        private SEQUENCE.Template seqt;

        public Template() {
            seqt = new SEQUENCE.Template();

            seqt.addElement( INTEGER.getTemplate() );
            seqt.addElement( AlgorithmIdentifier.getTemplate() );
            seqt.addElement( ContentInfo.getTemplate() );
            seqt.addElement( OCTET_STRING.getTemplate() );
        }

        public boolean tagMatch(Tag tag) {
            return TAG.equals(tag);
        }

        public ASN1Value decode(InputStream istream)
                throws InvalidBERException, IOException {
            return decode(TAG, istream);
        }

        public ASN1Value decode(Tag implicitTag, InputStream istream)
                throws InvalidBERException, IOException {

            SEQUENCE seq = (SEQUENCE) seqt.decode(implicitTag, istream);

            return new DigestedData(
                            (INTEGER) seq.elementAt(0),
                            (AlgorithmIdentifier) seq.elementAt(1),
                            (ContentInfo) seq.elementAt(2),
                            (OCTET_STRING) seq.elementAt(3) );
        }
    }
}
