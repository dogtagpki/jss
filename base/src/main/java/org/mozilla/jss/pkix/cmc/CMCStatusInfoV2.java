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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.mozilla.jss.asn1.ASN1Template;
import org.mozilla.jss.asn1.ASN1Value;
import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.asn1.Tag;
import org.mozilla.jss.asn1.UTF8String;

/**
 * CMCStatusInfoV2 replaces CMCStatusInfo in rfc 5272
 * CMC <i>CMCStatusInfoV2</i>:
 *
 * <pre>{@code
 *     CMCStatusInfoV2 ::= SEQUENCE {
 *          cMCStatus           CMCStatus,
 *          bodyList            SEQUENCE SIZE (1..MAX)
 *                                       BodyPartReference,
 *          statusString        UTF8String OPTIONAL,
 *          otherInfo           CHOICE {  // defined in updated OtherInfo
 *            failInfo            CMCFailInfo,
 *            pendInfo            PendInfo,
 *            extendedFailInfo       SEQUENCE {
 *              failInfoOID            OBJECT IDENTIFIER,
 *              failInfoValue          AttributeValue
 *            } OPTIONAL
 *         }
 *     }
 *     PendInfo ::= SEQUENCE {
 *          pendToken           OCTET STRING,
 *          pendTime            GeneralizedTime
 *     }
 * }</pre>
 *
 * @author Christina Fu (cfu)
 */
public class CMCStatusInfoV2 implements ASN1Value {
    public static final INTEGER BODYIDMAX = new INTEGER("4294967295");

    ///////////////////////////////////////////////////////////////////////
    // Members
    ///////////////////////////////////////////////////////////////////////
    private INTEGER status;
    private SEQUENCE bodyList;
    private UTF8String statusString;
    private OtherInfo otherInfo;

    // CMCStatus constants
    public static final int SUCCESS = 0;
    public static final int RESERVED = 1;
    public static final int FAILED = 2;
    public static final int PENDING = 3;
    public static final int NOSUPPORT = 4;
    public static final int CONFIRM_REQUIRED = 5;
    public static final int POP_REQUIRED = 6;
    public static final int PARTIAL = 7;

    public static final String[] STATUS = {"success",
                                           "reserved",
                                           "failed",
                                           "pending",
                                           "not supported",
                                           "confirm required",
                                           "pop required",
                                           "partial"};

    ///////////////////////////////////////////////////////////////////////
    // Constructors
    ///////////////////////////////////////////////////////////////////////

    /**
     * @param status A CMCStatus constant.
     * @param bodyList The sequence of BodyPartReference.
     */
    public CMCStatusInfoV2(int status, SEQUENCE bodyList) {
        this.status = new INTEGER(status);
        this.bodyList = bodyList;
        this.statusString = null;
        this.otherInfo = null;
    }

    /**
     * @param status A CMCStatus constant.
     * @param bodyList The sequence of BodyPartReference.
     * @param statusString A String.
     * @param otherInfo The OtherInfo choice.
     */
    public CMCStatusInfoV2(int status, SEQUENCE bodyList, String
                         statusString, OtherInfo otherInfo) {
        this.status = new INTEGER(status);
        this.bodyList = bodyList;
        if (statusString != null){
            try {
                this.statusString = new UTF8String(statusString);
            } catch (Exception e){}
        } else
            this.statusString = null;
        this.otherInfo = otherInfo;
    }

    /**
     * Create a CMCStatusInfoV2 from decoding.
     * @param status A CMCStatus constant.
     * @param bodyList The sequence of BodyPartReference.
     * @param statusString A UTF8String.
     * @param otherInfo A CHOICE.
     */
    public CMCStatusInfoV2(INTEGER status, SEQUENCE bodyList, UTF8String
                         statusString, OtherInfo otherInfo) {
        this.status = status;
        this.bodyList = bodyList;
        this.statusString = statusString;
        this.otherInfo = otherInfo;
    }

    /**
     * Sets the <code>statusString</code> field. May be null, since this
     *  field is optional.
     */
    public void setStatusString(String statusString) {
        if (statusString != null){
            try {
                this.statusString = new UTF8String(statusString);
            } catch (Exception e){}
        } else{
            this.statusString = null;
        }
    }

    /**
     * Adds a BodyPartID to the bodyList SEQUENCE.
     */
    public void addBodyPartID(int id) {
        INTEGER id1 = new INTEGER(id);
        assert(id1.compareTo(BODYIDMAX) <= 0);
        bodyList.addElement( id1 );
    }

    ///////////////////////////////////////////////////////////////////////
    // member access
    ///////////////////////////////////////////////////////////////////////
    public int getStatus() {
        return status.intValue();
    }

    public SEQUENCE getBodyList() {
        return bodyList;
    }

    public String getStatusString() {
        if (statusString != null)
            return statusString.toString();
        return null;
    }

    public OtherInfo getOtherInfo() {
        return otherInfo;
    }

    ///////////////////////////////////////////////////////////////////////
    // decoding/encoding
    ///////////////////////////////////////////////////////////////////////

    public static final Tag TAG = SEQUENCE.TAG;
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
        throws IOException
    {
        SEQUENCE seq = new SEQUENCE();

        seq.addElement(status);
        seq.addElement(bodyList);
        if( statusString != null ) {
            seq.addElement( statusString );
        }

        if ( otherInfo != null) {
            seq.addElement( otherInfo );
        }

        seq.encode(implicitTag, ostream);
    }

    private static final Template templateInstance = new Template();
    public static Template getTemplate() {
        return templateInstance;
    }


    public static class Template implements ASN1Template {

        private SEQUENCE.Template seqt;

        public Template() {
            seqt = new SEQUENCE.Template();
            seqt.addElement( INTEGER.getTemplate() );
            seqt.addElement( new SEQUENCE.OF_Template(INTEGER.getTemplate()) );
            seqt.addOptionalElement( UTF8String.getTemplate());

            seqt.addOptionalElement( OtherInfo.getTemplate() );
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

            CMCStatusInfoV2 psi;
            SEQUENCE seq = (SEQUENCE) seqt.decode(implicitTag, istream);

            return new CMCStatusInfoV2((INTEGER)seq.elementAt(0),
                                     (SEQUENCE)seq.elementAt(1),
                                     (UTF8String)seq.elementAt(2),
                                     (OtherInfo)seq.elementAt(3));
        }
    }
}

