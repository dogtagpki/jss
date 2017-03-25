/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkix.cmc;

import org.mozilla.jss.asn1.*;
import java.io.*;
import org.mozilla.jss.util.Assert;

/**
 * CMCStatusInfoV2 <i>OtherInfo</i>:
 *
 * <pre>
 *   OtherInfo ::= CHOICE { 
 *       failInfo INTEGER, 
 *       pendInfo PendInfo,
 *       extendedFailInfo       SEQUENCE {  // ExtendedFailInfo
 *           failInfoOID            OBJECT IDENTIFIER,
 *           failInfoValue          AttributeValue
 *       } OPTIONAL
 *   }
 * </pre>
 *
 * @author Christina Fu (cfu) - updated for rfc5272
 */
public class OtherInfo implements ASN1Value {
    // CMCFailInfo constants
    public static final int BAD_ALG = 0;
    public static final int BAD_MESSAGE_CHECK = 1;
    public static final int BAD_REQUEST = 2;
    public static final int BAD_TIME = 3;
    public static final int BAD_CERT_ID = 4;
    public static final int UNSUPORTED_EXT = 5;
    public static final int MUST_ARCHIVE_KEYS = 6;
    public static final int BAD_IDENTITY = 7;
    public static final int POP_REQUIRED = 8;
    public static final int POP_FAILED = 9;
    public static final int NO_KEY_REUSE = 10;
    public static final int INTERNAL_CA_ERROR = 11;
    public static final int TRY_LATER = 12;
    public static final int authDataFail = 13;

    public static final String[] FAIL_INFO = {
            "bad algorithm",
            "bad message check",
            "bad request",
            "bad time",
            "bad certificate id",
            "unsupported extensions",
            "must archive keys",
            "bad identity",
            "POP required",
            "POP failed",
            "no key reuse",
            "internal ca error",
            "try later",
            "authenticated data fail"};
    /**
     * The type of OtherInfo.
     */
    public static class Type {
        private Type() { }

        static Type FAIL = new Type();
        static Type PEND = new Type();
        static Type EXTENDED = new Type();
    }
    public static Type FAIL = Type.FAIL;
    public static Type PEND = Type.PEND;
    public static Type EXTENDED = Type.EXTENDED;

    ///////////////////////////////////////////////////////////////////////
    // members and member access
    ///////////////////////////////////////////////////////////////////////

    private Type type;
    private INTEGER failInfo; // if type == FAIL
    private PendInfo pendInfo; // if type == PEND
    private ExtendedFailInfo extendedFailInfo; // if type == EXTENDED

    ///////////////////////////////////////////////////////////////////////
    // Constructors
    ///////////////////////////////////////////////////////////////////////

    // no default constructor
    public OtherInfo() { }

    /**
     * Constructs a OtherInfo from its components.
     *
     * @param type The type of the otherInfo.
     * @param failInfo the CMCFailInfo code.
     * @param pendInfo the pending information.
     *
     * Note: kept for backward compatibility for now; new code don't use
     */
    public OtherInfo(Type type, INTEGER failInfo, PendInfo pendInfo) {
        if (type == null) {
            throw new IllegalArgumentException("OtherInfo constructor"
                +" parameter is null");
        }

        if ( type == FAIL ) {
            if (failInfo == null) {
                throw new IllegalArgumentException("OtherInfo constructor"
                    +" parameter failInfo is null");
            }
        } else {
            Assert._assert( type == PEND );
            if (pendInfo == null) {
                throw new IllegalArgumentException("OtherInfo constructor"
                    +" parameter pendInfo is null");
            }
        }
        this.type = type;
        this.failInfo = failInfo;
        this.pendInfo = pendInfo;
    }

    /** 
     * Constructs a OtherInfo from its components.
     *
     * @param type The type of the otherInfo.
     * @param failInfo the CMCFailInfo code.
     * @param pendInfo the pending information.
     * @param extendedFailInfo the extendedFailInfo information.
     */
    public OtherInfo(Type type,
            INTEGER failInfo,
            PendInfo pendInfo,
            ExtendedFailInfo extendedFailInfo) {
        if (type == null) {
            throw new IllegalArgumentException("OtherInfo constructor"
                +" parameter is null");
        }

        if ( type == FAIL ) {
            if (failInfo == null) {
                throw new IllegalArgumentException("OtherInfo constructor"
                    +" parameter failInfo is null");
            }
        } else if ( type == PEND ) {
            if (pendInfo == null) {
                throw new IllegalArgumentException("OtherInfo constructor"
                    +" parameter pendInfo is null");
            }
        } else {
            Assert._assert( type == EXTENDED );
            if (extendedFailInfo == null) {
                throw new IllegalArgumentException("OtherInfo constructor"
                    +" parameter extendedFailInfo is null");
            }
        }
        this.type = type;
        this.failInfo = failInfo;
        this.pendInfo = pendInfo;
        this.extendedFailInfo = extendedFailInfo;
    }

    ///////////////////////////////////////////////////////////////////////
    // accessors
    ///////////////////////////////////////////////////////////////////////

    /**
     * Returns the type of OtherInfo: <ul>
     * <li><code>FAIL</code>
     * <li><code>PEND</code>
     * <li><code>EXTENDED</code>
     * </ul>
     */
    public Type getType() {
        return type;
    }

    /**
     * If type == FAIL, returns the failInfo field. Otherwise,
     * returns null.
     */
    public INTEGER getFailInfo() {
        return failInfo;
    }

    /**
     * If type == PEND, returns the pendInfo field. Otherwise,
     * returns null.
     */
    public PendInfo getPendInfo() {
        return pendInfo;
    }

    /**
     * If type == EXTENDED, returns the extendedFailInfo field. Otherwise,
     * returns null.
     */
    public ExtendedFailInfo getExtendedFailInfo() {
        return extendedFailInfo;
    }

    ///////////////////////////////////////////////////////////////////////
    // DER decoding/encoding
    ///////////////////////////////////////////////////////////////////////

    public Tag getTag() {
        // return the subType's tag
        if( type == FAIL ) {
            return INTEGER.TAG;
        } else if( type == PEND ){
            return PendInfo.TAG;
        } else {
            Assert._assert( type == EXTENDED );
            return ExtendedFailInfo.TAG;
        }
    }

    public void encode(OutputStream ostream) throws IOException {

        if( type == FAIL ) {
            failInfo.encode(ostream);
        } else if( type == PEND ){
            pendInfo.encode(ostream);
        } else {
            Assert._assert( type == EXTENDED );
            extendedFailInfo.encode(ostream);
        }
    }

    public void encode(Tag implicitTag, OutputStream ostream)
            throws IOException {
            //Assert.notReached("A CHOICE cannot be implicitly tagged " +implicitTag.getNum());
            encode(ostream);
    }

    private static final Template templateInstance = new Template();
    public static Template getTemplate() {
        return templateInstance;
    }

    /**
     * A Template for decoding a OtherInfo.
     */
    public static class Template implements ASN1Template {

        private CHOICE.Template choicet;

        public Template() {
            choicet = new CHOICE.Template();
            choicet.addElement( INTEGER.getTemplate() );
            choicet.addElement( PendInfo.getTemplate() );
            choicet.addElement( ExtendedFailInfo.getTemplate() );
        }

        public boolean tagMatch(Tag tag) {
            return choicet.tagMatch(tag);
        }

        public ASN1Value decode(InputStream istream)
                throws InvalidBERException, IOException {
            CHOICE c = (CHOICE) choicet.decode(istream);

            if( c.getTag().equals(INTEGER.TAG) ) {
                return new OtherInfo(FAIL, (INTEGER) c.getValue() , null, null);
            } else if( c.getTag().equals(PendInfo.TAG) ) {
                return new OtherInfo(PEND, null, (PendInfo) c.getValue(), null);
            } else {
                Assert._assert( c.getTag().equals(ExtendedFailInfo.TAG) );
                return new OtherInfo(EXTENDED, null, null, (ExtendedFailInfo) c.getValue());
            }
        }

        public ASN1Value decode(Tag implicitTag, InputStream istream)
                throws InvalidBERException, IOException {
                //Assert.notReached("A CHOICE cannot be implicitly tagged");
                return decode(istream);
        }
    }
}
