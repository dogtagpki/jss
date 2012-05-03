/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkix.cms;

import org.mozilla.jss.asn1.*;
import org.mozilla.jss.pkix.primitive.*;
import java.io.*;

public class SignedAndEnvelopedData implements ASN1Value {

    ///////////////////////////////////////////////////////////////////////
    // members and member access
    ///////////////////////////////////////////////////////////////////////
    private INTEGER version;
    private SET recipientInfos;
    private SET digestAlgorithms;
    private EncryptedContentInfo encryptedContentInfo;
    private SET certificates; // may be null
    private SET crls; // may be null
    private SET signerInfos;
    private SEQUENCE sequence; // for encoding

    /**
     * Returns the version number.  The current version is 1.
     */
    public INTEGER getVersion() {
        return version;
    }

    /**
     * Returns a SET of RecipientInfo.
     */
    public SET getRecipientInfos() {
        return recipientInfos;
    }

    /**
     * Returns a SET of AlgorithmIdentifier.
     */
    public SET getDigestAlgorithms() {
        return digestAlgorithms;
    }

    /**
     * Returns the encrypted content.
     */
    public EncryptedContentInfo getEncryptedContentInfo() {
        return encryptedContentInfo;
    }

    /**
     * Returns a SET of ANYs. May return <code>null</code> if the
     * <i>certificates</i> field is not present.
     */
    public SET getCertificates() {
        return certificates;
    }

    /**
     * Returns a SET of ANYs. May return <code>null</code> if the <i>crls</i>
     * field is not present.
     */
    public SET getCrls() {
        return crls;
    }

    /**
     * Returns a SET of SignerInfo.
     */
    public SET getSignerInfos() {
        return signerInfos;
    }

    ///////////////////////////////////////////////////////////////////////
    // Constructors
    ///////////////////////////////////////////////////////////////////////

    private SignedAndEnvelopedData() { }

    public SignedAndEnvelopedData(
                        INTEGER version,
                        SET recipientInfos,
                        SET digestAlgorithms,
                        EncryptedContentInfo encryptedContentInfo,
                        SET certificates,
                        SET crls,
                        SET signerInfos)
    {
        if( version==null || recipientInfos==null || digestAlgorithms==null
            || encryptedContentInfo==null || signerInfos==null ) {
            throw new IllegalArgumentException(
                "SignedAndEnvelopedData constructor parameter is null");
        }

        this.version = version;
        this.recipientInfos = recipientInfos;
        this.digestAlgorithms = digestAlgorithms;
        this.encryptedContentInfo = encryptedContentInfo;
        this.certificates = certificates;
        this.crls = crls;
        this.signerInfos = signerInfos;

        sequence = new SEQUENCE();
        sequence.addElement(version);
        sequence.addElement(recipientInfos);
        sequence.addElement(digestAlgorithms);
        sequence.addElement(encryptedContentInfo);
        if( certificates!=null ) {
            sequence.addElement(certificates);
        }
        if( crls!=null ) {
            sequence.addElement(crls);
        }
        sequence.addElement( signerInfos );
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
        throws IOException
    {
        sequence.encode(implicitTag, ostream);
    }


    /**
     * A Template class for decoding BER-encoded SignedAndEnvelopedData items.
     */
    public static class Template implements ASN1Template {

        private SEQUENCE.Template seqt;

        public Template() {
            seqt = new SEQUENCE.Template();

            seqt.addElement(INTEGER.getTemplate());
            seqt.addElement(new SET.OF_Template(RecipientInfo.getTemplate()));
            seqt.addElement(new SET.OF_Template(
                                    AlgorithmIdentifier.getTemplate()) );
            seqt.addElement(EncryptedContentInfo.getTemplate());
            seqt.addOptionalElement(new Tag(0),
                    new SET.OF_Template(ANY.getTemplate()));
            seqt.addOptionalElement(new Tag(1),
                    new SET.OF_Template(ANY.getTemplate()));
            seqt.addElement(new SET.OF_Template(SignerInfo.getTemplate()));
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
            SEQUENCE seq = (SEQUENCE) seqt.decode(implicitTag, istream);

            return new SignedAndEnvelopedData(
                        (INTEGER) seq.elementAt(0),
                        (SET) seq.elementAt(1),
                        (SET) seq.elementAt(2),
                        (EncryptedContentInfo) seq.elementAt(3),
                        (SET) seq.elementAt(4),
                        (SET) seq.elementAt(5),
                        (SET) seq.elementAt(6) );
        }
    }
}
