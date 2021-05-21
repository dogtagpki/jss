/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkix.crmf;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.mozilla.jss.asn1.ASN1Template;
import org.mozilla.jss.asn1.ASN1Value;
import org.mozilla.jss.asn1.BIT_STRING;
import org.mozilla.jss.asn1.CHOICE;
import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.Tag;

/**
 * CRMF <i>POPOPrivKey</i>:
 * <pre>
 * POPOPrivKey ::= CHOICE {
 *      thisMessage         [0] BIT STRING,
 *      subsequentMessage   [1] SubsequentMessage,
 *      dhMAC               [2] BIT STRING }
 *
 * SubsequentMessage ::= INTEGER {
 *      encrCert        (0),
 *      challengeResp   (1) }
 * </pre>
 */
public class POPOPrivKey implements ASN1Value {

    /**
     * The type of POPOPrivKey.
     */
    public static class Type {
        private Type() { }

        static final Type THIS_MESSAGE = new Type();
        static final Type SUBSEQUENT_MESSAGE = new Type();
        static final Type DHMAC = new Type();
    }
    public static final Type THIS_MESSAGE = Type.THIS_MESSAGE;
    public static final Type SUBSEQUENT_MESSAGE = Type.SUBSEQUENT_MESSAGE;
    public static final Type DHMAC = Type.DHMAC;

    /**
     * The SubsequentMessage field is <code>encrCert</code>.
     */
    public static final int ENCR_CERT = 0;

    /**
     * The SubsequentMessage field is <code>challengeResp</code>.
     */
    public static final int CHALLENGE_RESP = 1;


    ///////////////////////////////////////////////////////////////////////
    // Members and member access
    ///////////////////////////////////////////////////////////////////////
    private Type type;
    private BIT_STRING thisMessage; // if type == THIS_MESSAGE
    private INTEGER subsequentMessage; // if type == SUBSEQUENT_MESSAGE
    private BIT_STRING dhMAC; // if type == DHMAC

    /**
     * Returns the type of POPOPrivKey: THIS_MESSAGE, SUBSEQUENT_MESSAGE,
     *  or DHMAC.
     */
    public Type getType() {
        return type;
    }

    /**
     * If type==THIS_MESSAGE, returns the thisMessage field. Otherwise,
     *      returns null.
     */
    public BIT_STRING getThisMessage() {
        return thisMessage;
    }

    /**
     * If type==SUBSEQUENT_MESSAGE, returns the subsequentMessage field.
     *  Otherwise, returns null.  The return value can be converted to an
     *  integer and compared with ENCR_CERT and CHALLENGE_RESP.
     */
    public INTEGER getSubsequentMessage() {
        return subsequentMessage;
    }

    /**
     * If type==DHMAC, returns the dhMAC field. Otherwise, returns null.
     */
    public BIT_STRING getDhMAC() {
        return dhMAC;
    }

    ///////////////////////////////////////////////////////////////////////
    // Constructors
    ///////////////////////////////////////////////////////////////////////
    private POPOPrivKey() { }

    private POPOPrivKey(Type type, BIT_STRING thisMessage,
                INTEGER subsequentMessage, BIT_STRING dhMAC) {
        this.type = type;
        this.thisMessage = thisMessage;
        this.subsequentMessage = subsequentMessage;
        this.dhMAC = dhMAC;
    }

    /**
     * Creates a new POPOPrivKey with the given thisMessage field.
     */
    public static POPOPrivKey createThisMessage(BIT_STRING thisMessage) {
        return new POPOPrivKey(THIS_MESSAGE, thisMessage, null, null);
    }

    /**
     * Creates a new POPOPrivKey with the given subsequentMessage field.
     */
    public static POPOPrivKey createSubsequentMessage(int subsequentMessage) {
        if(subsequentMessage!=ENCR_CERT && subsequentMessage!=CHALLENGE_RESP) {
            throw new IllegalArgumentException(
                "Illegal subsequentMessage value: " + subsequentMessage );
        }

        return new POPOPrivKey(SUBSEQUENT_MESSAGE, null,
                        new INTEGER(subsequentMessage), null);
    }

    /**
     * Creates a new POPOPrivKey with the given dhMAC field.
     */
    public static POPOPrivKey createDhMAC(BIT_STRING dhMAC) {
        return new POPOPrivKey(DHMAC, null, null, dhMAC);
    }

    ///////////////////////////////////////////////////////////////////////
    // encoding/decoding
    ///////////////////////////////////////////////////////////////////////

    @Override
    public Tag getTag() {
        if(type == THIS_MESSAGE) {
            return Tag.get(0);
        } else if(type == SUBSEQUENT_MESSAGE) {
            return Tag.get(1);
        } else {
            assert(type == DHMAC);
            return Tag.get(2);
        }
    }

    @Override
    public void encode(OutputStream ostream) throws IOException {
        if(type == THIS_MESSAGE) {
            thisMessage.encode(Tag.get(0), ostream);
        } else if(type == SUBSEQUENT_MESSAGE) {
            subsequentMessage.encode(Tag.get(1), ostream);
        } else {
            assert(type == DHMAC);
            dhMAC.encode(Tag.get(2), ostream);
        }
    }

    /**
     * Should not be called, because POPOPrivKey is a CHOICE and cannot have
     * an implicit tag.
     */
    @Override
    public void encode(Tag implicitTag, OutputStream ostream)
            throws IOException {
        throw new RuntimeException("POPOPrivKey is a CHOICE and cannot have an implicit tag");
        // encode(ostream);
    }

    private static final Template templateInstance = new Template();
    public static Template getTemplate() {
        return templateInstance;
    }

    /**
     * A Template for decoding a POPOPrivKey.
     */
    public static class Template implements ASN1Template {

        private CHOICE.Template choicet;

        public Template() {
            choicet = new CHOICE.Template();

            choicet.addElement( Tag.get(0), BIT_STRING.getTemplate() );
            choicet.addElement( Tag.get(1), INTEGER.getTemplate() );
            choicet.addElement( Tag.get(2), BIT_STRING.getTemplate() );
        }

        @Override
        public boolean tagMatch(Tag tag) {
            return choicet.tagMatch(tag);
        }

        /**
         * Should not be called, because POPOPrivKey is a CHOICE and cannot
         * have an implicit tag.
         */
        @Override
        public ASN1Value decode(Tag implicitTag, InputStream istream)
                throws InvalidBERException, IOException {
            throw new RuntimeException("POPOPrivKey is a CHOICE and cannot have an implicitTag");
            // return decode(istream);
        }

        @Override
        public ASN1Value decode(InputStream istream)
                throws InvalidBERException, IOException {

            CHOICE choice = (CHOICE) choicet.decode(istream);

            Tag chosen = choice.getTag();

            if( chosen.equals(Tag.get(0)) ) {
                return createThisMessage( (BIT_STRING) choice.getValue() );
            } else if( chosen.equals(Tag.get(1)) ) {
                INTEGER I = (INTEGER) choice.getValue();
                int i = I.intValue();
                if( i != ENCR_CERT && i != CHALLENGE_RESP ) {
                    throw new InvalidBERException(
                        "SubsequentMessage has invalid value: "+i);
                }
                return createSubsequentMessage( i );
            } else {
                assert( chosen.equals(Tag.get(2)) );
                return createDhMAC( (BIT_STRING) choice.getValue() );
            }
        }
    }
}
