/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkix.crmf;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.mozilla.jss.asn1.ANY;
import org.mozilla.jss.asn1.ASN1Template;
import org.mozilla.jss.asn1.ASN1Value;
import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.asn1.Tag;

/**
 * CRMF <i>PKIPublicationInfo</i>:
 * <pre>
 * PKIPublicationInfo ::= SEQUENCE {
 *      action          INTEGER {
 *          dontPublish     (0),
 *          pleasePublish   (1) },
 *      pubInfos SEQUENCE SIZE (1..MAX) OF SinglePubInfo OPTIONAL }
 *
 * SinglePubInfo ::= SEQUENCE {
 *      pubMethod       INTEGER {
 *          dontCare    (0),
 *          x500        (1),
 *          web         (2),
 *          ldap        (3) },
 *      pubLocation     GeneralName OPTIONAL }
 * </pre>
 */
public class PKIPublicationInfo implements ASN1Value {

    /**
     * A PKIPublicationInfo action.
     */
    public static final int DONT_PUBLISH = 0;
    /**
     * A PKIPublicationInfo action.
     */
    public static final int PLEASE_PUBLISH = 1;

    /**
     * A SinglePubInfo publication method.
     */
    public static final int DONT_CARE = 0;
    /**
     * A SinglePubInfo publication method.
     */
    public static final int X500 = 1;
    /**
     * A SinglePubInfo publication method.
     */
    public static final int WEB = 2;
    /**
     * A SinglePubInfo publication method.
     */
    public static final int LDAP = 3;

    ///////////////////////////////////////////////////////////////////////
    // members and member access
    ///////////////////////////////////////////////////////////////////////

    private int action;
    private SEQUENCE pubInfos; // may be null

    /**
     * Returns the action field.
     */
    public int getAction() {
        return action;
    }

    /**
     * Returns the number of SinglePubInfos.  May be zero.
     */
    public int numPubInfos() {
        if( pubInfos == null ) {
            return 0;
        } else {
            return pubInfos.size();
        }
    }

    /**
     * Returns the pubMethod in the SinglePubInfo at the given index.
     * Should return DONT_CARE, X500, WEB, or LDAP.
     */
    public int getPubMethod(int index) {
        return ((INTEGER)((SEQUENCE)pubInfos.elementAt(index)).
                        elementAt(0)).intValue();
    }

    /**
     * Returns the pubLocation in the SinglePubInfo at the given index.
     * May return null, since pubLocation is an optional field.
     */
    public ANY getPubLocation(int index) {
        return (ANY) ((SEQUENCE)pubInfos.elementAt(index)).elementAt(1);
    }

    ///////////////////////////////////////////////////////////////////////
    // constructors
    ///////////////////////////////////////////////////////////////////////

    /**
     * Creates a new PKIPublicationInfo.
     * @param action DONT_PUBLISH or PLEASE_PUBLISH.
     * @param pubInfos A SEQUENCE of SinglePubInfo, may be null.
     */
    public PKIPublicationInfo(int action, SEQUENCE pubInfos) {
        this.action = action;
        this.pubInfos = pubInfos;
    }

    ///////////////////////////////////////////////////////////////////////
    // decoding/encoding
    ///////////////////////////////////////////////////////////////////////

    private static final Tag TAG = SEQUENCE.TAG;

    @Override
    public Tag getTag() {
        return TAG;
    }

    @Override
    public void encode(OutputStream ostream) throws IOException {
        encode(TAG, ostream);
    }

    @Override
    public void encode(Tag implicitTag, OutputStream ostream)
            throws IOException {
        SEQUENCE seq = new SEQUENCE();

        seq.addElement( new INTEGER(action) );
        seq.addElement( pubInfos );

        seq.encode(implicitTag, ostream);
    }

    private static final Template templateInstance = new Template();

    public static Template getTemplate() {
        return templateInstance;
    }

    /**
     * A Template for decoding a PKIPublicationInfo.
     */
    public static class Template implements ASN1Template {

        private SEQUENCE.Template seqt;

        public Template() {
            seqt = new SEQUENCE.Template();
            seqt.addElement( INTEGER.getTemplate() );

            SEQUENCE.Template pubInfot = new SEQUENCE.Template();
            pubInfot.addElement(INTEGER.getTemplate());
            pubInfot.addOptionalElement(ANY.getTemplate());

            seqt.addOptionalElement( new SEQUENCE.OF_Template(pubInfot) );
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

            return new PKIPublicationInfo(
                            ((INTEGER)seq.elementAt(0)).intValue(),
                            (SEQUENCE) seq.elementAt(1) );
        }
    }
}
