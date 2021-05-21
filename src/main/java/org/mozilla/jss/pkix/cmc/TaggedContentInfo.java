/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkix.cmc;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.mozilla.jss.asn1.ASN1Template;
import org.mozilla.jss.asn1.ASN1Value;
import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.asn1.Tag;
import org.mozilla.jss.pkix.cms.ContentInfo;

/**
 * CMC <i>TaggedContentInfo</i>.
 * <pre>
 * The definition of TaggedContentInfo comes from RFC 2797 Section 3.6.
 * TaggedContentInfo ::= SEQUENCE {
 *      bodyPartID      BodyPartID,
 *      contentInfo     ContentInfo}
 * </pre>
 */
public class TaggedContentInfo implements ASN1Value {

    ///////////////////////////////////////////////////////////////////////
    // Members and member access
    ///////////////////////////////////////////////////////////////////////
    private INTEGER bodyPartID;
    private ContentInfo contentInfo;
    private SEQUENCE sequence;

    /**
     * Returns the <code>bodyPartID</code> field.
     */
    public INTEGER getBodyPartID() {
        return bodyPartID;
    }

    /**
     * Returns the <code>contentInfo</code> field.
     */
    public ContentInfo getContentInfo() {
        return contentInfo;
    }

    ///////////////////////////////////////////////////////////////////////
    // Constructors
    ///////////////////////////////////////////////////////////////////////

    /**
     * Constructs a new <code>TaggedContentInfo</code> from its components.
     */
    public TaggedContentInfo(INTEGER bodyPartID, ContentInfo contentInfo) {
        if (bodyPartID == null || contentInfo == null) {
            throw new IllegalArgumentException(
                "parameter to TaggedContentInfo constructor is null");
        }
        sequence = new SEQUENCE();

        this.bodyPartID = bodyPartID;
        sequence.addElement(bodyPartID);

        this.contentInfo = contentInfo;
        sequence.addElement(contentInfo);
    }

    ///////////////////////////////////////////////////////////////////////
    // encoding/decoding
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
            throws IOException {
        sequence.encode(implicitTag, ostream);
    }

    private static final Template templateInstance = new Template();
    public static Template getTemplate() {
        return templateInstance;
    }

    /**
     * A Template for decoding a <code>TaggedContentInfo</code>.
     */
    public static class Template implements ASN1Template {
        private SEQUENCE.Template seqt;

        public Template() {
            seqt = new SEQUENCE.Template();
            seqt.addElement(INTEGER.getTemplate());
            seqt.addElement(ContentInfo.getTemplate());
        }

        @Override
        public boolean tagMatch(Tag tag) {
            return TAG.equals(tag);
        }

        @Override
        public ASN1Value decode(InputStream istream)
                throws InvalidBERException, IOException {
            return decode(TAG, istream);
        }

        @Override
        public ASN1Value decode(Tag implicitTag, InputStream istream)
                throws InvalidBERException, IOException {
            SEQUENCE seq = (SEQUENCE) seqt.decode(implicitTag, istream);

            return new TaggedContentInfo((INTEGER)seq.elementAt(0),
                                         (ContentInfo)seq.elementAt(1));
        }
    }
}
