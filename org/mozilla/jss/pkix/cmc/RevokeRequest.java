/* ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is the Netscape Security Services for Java.
 *
 * The Initial Developer of the Original Code is
 * Netscape Communications Corporation.
 * Portions created by the Initial Developer are Copyright (C) 1998-2000
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either the GNU General Public License Version 2 or later (the "GPL"), or
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the MPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the MPL, the GPL or the LGPL.
 *
 * ***** END LICENSE BLOCK ***** */

package org.mozilla.jss.pkix.cmc;

import org.mozilla.jss.asn1.*;
import java.io.*;

/**
 * CMC <i>RevokeRequest</i>.
 * <pre>
 * RevokeRequest ::= SEQUENCE {
 *      issuerName      Name,
 *      serialNumber    INTEGER,
 *      reason          CRLReason,
 *      invalidityDate  GeneralizedTime OPTIONAL,
 *      passphrase    OCTET STRING OPTIONAL,
 *      comment         UTF8String OPTIONAL }
 * </pre>
 *
 * For maintenance and conformance reasons, this code is brought over
 * and mildly updated and renamed from cmmf/RevRequest during the process
 * of CMC update to rfc 5272
 * @author Christina Fu (cfu)
 */
public class RevokeRequest implements ASN1Value {

    ///////////////////////////////////////////////////////////////////////
    // Constants
    ///////////////////////////////////////////////////////////////////////

    /**
     * A <code>CRLReason</code>, which can be used in the <code>reason</code>
     *  field.
     */
    public static final ENUMERATED unspecified = new ENUMERATED(0);
    /**
     * A <code>CRLReason</code>, which can be used in the <code>reason</code>
     *  field.
     */
    public static final ENUMERATED keyCompromise = new ENUMERATED(1);
    /**
     * A <code>CRLReason</code>, which can be used in the <code>reason</code>
     *  field.
     */
    public static final ENUMERATED cACompromise = new ENUMERATED(2);
    /**
     * A <code>CRLReason</code>, which can be used in the <code>reason</code>
     *  field.
     */
    public static final ENUMERATED affiliationChanged = new ENUMERATED(3);
    /**
     * A <code>CRLReason</code>, which can be used in the <code>reason</code>
     *  field.
     */
    public static final ENUMERATED superseded = new ENUMERATED(4);
    /**
     * A <code>CRLReason</code>, which can be used in the <code>reason</code>
     *  field.
     */
    public static final ENUMERATED cessationOfOperation = new ENUMERATED(5);
    /**
     * A <code>CRLReason</code>, which can be used in the <code>reason</code>
     *  field.
     */
    public static final ENUMERATED certificateHold = new ENUMERATED(6);
    /**
     * A <code>CRLReason</code>, which can be used in the <code>reason</code>
     *  field.
     */
    public static final ENUMERATED removeFromCRL = new ENUMERATED(8);
    /**
     * A <code>CRLReason</code>, which can be used in the <code>reason</code>
     *  field.
     */
    public static final ENUMERATED privilegeWithdrawn = new ENUMERATED(9);
    /**
     * A <code>CRLReason</code>, which can be used in the <code>reason</code>
     *  field.
     */
    public static final ENUMERATED aACompromise = new ENUMERATED(10);


    ///////////////////////////////////////////////////////////////////////
    // Members and member access
    ///////////////////////////////////////////////////////////////////////
    private ANY issuerName;
    private INTEGER serialNumber;
    private ENUMERATED reason;
    private GeneralizedTime invalidityDate; // may be null
    private OCTET_STRING passphrase; // may be null
    private UTF8String comment; // may be null
    private SEQUENCE sequence;

    /**
     * Returns the <code>issuerName</code> field as an ANY.
     */
    public ANY getIssuerName() {
        return issuerName;
    }

    /**
     * Returns the <code>serialNumber</code> field.
     */
    public INTEGER getSerialNumber() {
        return serialNumber;
    }

    /**
     * Returns the <code>reason</code> field, which should indicate the
     *  reason for the revocation.  The currently supported reasons are:
     * <pre>
     * CRLReason ::= ENUMERATED {
     *      unspecified             (0),
     *      keyCompromise           (1),
     *      cACompromise            (2),
     *      affiliationChanged      (3),
     *      superseded              (4),
     *      cessationOfOperation    (5),
     *      certificateHold         (6),
     *      removeFromCRL           (8),
     *      privilegeWithdrawn      (9),
     *      aACompromise            (10) }
     * </pre>
     * These are all defined as constants in this class.
     */
    public ENUMERATED getReason() {
        return reason;
    }

    /**
     * Returns the <tt>invalidityDate</tt> field. Returns <tt>null</tt>
     * if the field is not present.
     */
    public GeneralizedTime getInvalidityDate() {
        return invalidityDate;
    }

    /**
     * Returns the <code>passphrase</code> field.  Returns
     *  <code>null</code> if the field is not present.
     */
    public OCTET_STRING getSharedSecret() {
        return passphrase;
    }

    /**
     * Returns the <code>comment</code> field.  Returns <code>null</code>
     * if the field is not present.
     */
    public UTF8String getComment() {
        return comment;
    }

    ///////////////////////////////////////////////////////////////////////
    // Constructors
    ///////////////////////////////////////////////////////////////////////

    private RevokeRequest() { }


    /**
     * Constructs a new <code>RevokeRequest</code> from its components,
     *  omitting the <tt>invalidityDate</tt> field.
     *
     * @deprecated This constructor is obsolete now that
     *      <tt>invalidityDate</tt> has been added to the class.
     *
     * @param issuerName The <code>issuerName</code> field.
     * @param serialNumber The <code>serialNumber</code> field.
     * @param reason The <code>reason</code> field.  The constants defined
     *      in this class may be used.
     * @param passphrase The <code>passphrase</code> field.  This field is
     *      optional, so <code>null</code> may be used.
     * @param comment The <code>comment</code> field.  This field is optional,
     *      so <code>null</code> may be used.
     */
    public RevokeRequest(ANY issuerName, INTEGER serialNumber,
                    ENUMERATED reason, OCTET_STRING passphrase,
                    UTF8String comment)
    {
        this(issuerName, serialNumber, reason, null, passphrase, comment);
    }

    /**
     * Constructs a new <code>RevokeRequest</code> from its components.
     *
     * @param issuerName The <code>issuerName</code> field.
     * @param serialNumber The <code>serialNumber</code> field.
     * @param reason The <code>reason</code> field.  The constants defined
     *      in this class may be used.
     * @param invalidityDate The suggested value for the Invalidity Date
     *      CRL extension. This field is optional, so <tt>null</tt> may be
     *      used.
     * @param passphrase The <code>passphrase</code> field.  This field is
     *      optional, so <code>null</code> may be used.
     * @param comment The <code>comment</code> field.  This field is optional,
     *      so <code>null</code> may be used.
     */
    public RevokeRequest(ANY issuerName, INTEGER serialNumber,
                    ENUMERATED reason, GeneralizedTime invalidityDate,
                    OCTET_STRING passphrase, UTF8String comment)
    {
        if( issuerName==null || serialNumber==null || reason==null ) {
            throw new IllegalArgumentException(
                "parameter to RevokeRequest constructor is null");
        }
        sequence = new SEQUENCE();

        this.issuerName = issuerName;
        sequence.addElement(issuerName);

        this.serialNumber = serialNumber;
        sequence.addElement(serialNumber);

        this.reason = reason;
        sequence.addElement(reason);

        this.invalidityDate = invalidityDate;
        sequence.addElement(invalidityDate);

        this.passphrase = passphrase;
        sequence.addElement(passphrase);

        this.comment = comment;
        sequence.addElement(comment);
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



    /**
     * A Template class for decoding a <code>RevokeRequest</code>.
     */
    public static class Template implements ASN1Template {

        private SEQUENCE.Template seqt;

        public Template() {
            seqt = new SEQUENCE.Template();
            seqt.addElement(ANY.getTemplate());
            seqt.addElement(INTEGER.getTemplate());
            seqt.addElement(ENUMERATED.getTemplate());
            seqt.addOptionalElement(GeneralizedTime.getTemplate());
            seqt.addOptionalElement(OCTET_STRING.getTemplate());
            seqt.addOptionalElement(UTF8String.getTemplate());
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

            return new RevokeRequest(  (ANY) seq.elementAt(0),
                                    (INTEGER) seq.elementAt(1),
                                    (ENUMERATED) seq.elementAt(2),
                                    (GeneralizedTime) seq.elementAt(3),
                                    (OCTET_STRING) seq.elementAt(4),
                                    (UTF8String) seq.elementAt(5) );

        }
    }
}
