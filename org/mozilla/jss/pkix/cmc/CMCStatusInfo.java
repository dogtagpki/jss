/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */


package org.mozilla.jss.pkix.cmc;

import org.mozilla.jss.util.Assert;
import org.mozilla.jss.asn1.*;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.BitSet;

/**
 * CMC <i>CMCStatusInfo</i>:
 * <pre>
 *     CMCStatusInfo ::= SEQUENCE {
 *          cMCStatus           CMCStatus,
 *          bodyList            SEQUENCE SIZE (1..MAX) OF BodyPartID,
 *          statusString        UTF8String OPTIONAL,
 *          otherInfo           CHOICE {
 *            failInfo            CMCFailInfo,
 *            pendInfo            PendInfo } OPTIONAL
 *     }
 *     PendInfo ::= SEQUENCE {
 *          pendToken           OCTET STRING,
 *          pendTime            GeneralizedTime
 *     }
 * </pre>
 */
public class CMCStatusInfo implements ASN1Value {
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

    public static final String[] STATUS = {"success",
										   "reserved",
										   "failed",
										   "pending",
										   "not supported",
										   "confirm required"};

    ///////////////////////////////////////////////////////////////////////
    // Constructors
    ///////////////////////////////////////////////////////////////////////

    private CMCStatusInfo() { }

    /**
     * @param status A CMCStatus constant.
     * @param bodyList The sequence of bodyPartID.
     */
    public CMCStatusInfo(int status, SEQUENCE bodyList) {
        this.status = new INTEGER(status);
		this.bodyList = bodyList;
        this.statusString = null;
		this.otherInfo = null;
    }

    /**
     * @param status A CMCStatus constant.
     * @param bodyList The sequence of bodyPartID.
     * @param statusString A String.
     * @param otherInfo The OtherInfo choice.
     */
    public CMCStatusInfo(int status, SEQUENCE bodyList, String
						 statusString, OtherInfo otherInfo) {
        this.status = new INTEGER(status);
		this.bodyList = bodyList;
		if (statusString != null){
			try{
			    this.statusString = new UTF8String(statusString);
			}catch (Exception e){}
		}else
			this.statusString = null;
        this.otherInfo = otherInfo;
    }

    /**
     * Create a CMCStatusInfo from decoding.
     * @param status A CMCStatus constant.
     * @param bodyList The sequence of bodyPartID.
     * @param statusString A UTF8String.
     * @param otherInfo A CHOICE.
     */
    public CMCStatusInfo(INTEGER status, SEQUENCE bodyList, UTF8String
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
			try{
				this.statusString = new UTF8String(statusString);
			}catch (Exception e){}
		}else{
			this.statusString = null;
		}
    }

    /**
     * Adds a BodyPartID to the bodyList SEQUENCE.
     */
    public void addBodyPartID(int id) {
		INTEGER id1 = new INTEGER(id);
        Assert._assert(id1.compareTo(BODYIDMAX) <= 0);
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
    public Tag getTag() {
        return TAG;
    }

    public void encode(OutputStream ostream) throws IOException {
        encode(TAG, ostream);
    }

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

        public boolean tagMatch(Tag tag) {
            return TAG.equals(tag);
        }

        public ASN1Value decode(InputStream istream)
                throws InvalidBERException, IOException {
            return decode(TAG, istream);
        }

        public ASN1Value decode(Tag implicitTag, InputStream istream)
                throws InvalidBERException, IOException {

            CMCStatusInfo psi;
            SEQUENCE seq = (SEQUENCE) seqt.decode(implicitTag, istream);

			return new CMCStatusInfo((INTEGER)seq.elementAt(0),
									 (SEQUENCE)seq.elementAt(1),
									 (UTF8String)seq.elementAt(2),
									 (OtherInfo)seq.elementAt(3));
        }
    }
}

