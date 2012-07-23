/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkix.cmc;

import org.mozilla.jss.asn1.*;
import java.io.*;

/**
 * CMC <i>OtherMsg</i>.
 * <pre>
 * The definition of OtherMsg comes from RFC 2797.
 * OtherMsg ::= SEQUENCE {
 *      bodyPartID      BodyPartID,
 *      otherMsgType    Object Identifier,
 *      otherMsgValue   ANY defined by otherMsgType}
 * </pre>
 */
public class OtherMsg implements ASN1Value {

    ///////////////////////////////////////////////////////////////////////
    // Members and member access
    ///////////////////////////////////////////////////////////////////////
    private INTEGER bodyPartID;
    private OBJECT_IDENTIFIER otherMsgType;
    private ANY otherMsgValue;
    private SEQUENCE sequence;

    /**
     * Returns the <code>bodyPartID</code> field.
     */
    public INTEGER getBodyPartID() {
        return bodyPartID;
    }

    /**
     * Returns the <code>otherMsgType</code> field.
     */
    public OBJECT_IDENTIFIER getOtherMsgType() {
        return otherMsgType;
    }

    /**
     * Returns the <code>otherMsgValue</code> field.
     */
    public ANY getOtherMsgValue() {
        return otherMsgValue;
    }

    ///////////////////////////////////////////////////////////////////////
    // Constructors
    ///////////////////////////////////////////////////////////////////////
    private OtherMsg() { }

    /**
     * Constructs a new <code>OtherMsg</code> from its components.
     */
    public OtherMsg(INTEGER bodyPartID, OBJECT_IDENTIFIER otherMsgType,
            ANY otherMsgValue) {
        if (bodyPartID == null || otherMsgType == null
                || otherMsgValue == null) {
            throw new IllegalArgumentException(
                "parameter to OtherMsg constructor is null");
        }
        sequence = new SEQUENCE();

        this.bodyPartID = bodyPartID;
        sequence.addElement(bodyPartID);

        this.otherMsgType = otherMsgType;
        sequence.addElement(otherMsgType);

        this.otherMsgValue = otherMsgValue;
        sequence.addElement(otherMsgValue);
    }

    ///////////////////////////////////////////////////////////////////////
    // encoding/decoding
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

    private static final Template templateInstance = new Template();
    public static Template getTemplate() {
        return templateInstance;
    }

    /**
     * A Template for decoding a <code>OtherMsg</code>.
     */
    public static class Template implements ASN1Template {
        private SEQUENCE.Template seqt;

        public Template() {
            seqt = new SEQUENCE.Template();
            seqt.addElement(INTEGER.getTemplate());
            seqt.addElement(OBJECT_IDENTIFIER.getTemplate());
            seqt.addElement(ANY.getTemplate());
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

            return new OtherMsg((INTEGER)seq.elementAt(0),
                                (OBJECT_IDENTIFIER)seq.elementAt(1),
                                (ANY)seq.elementAt(2));
        }
    }
}
