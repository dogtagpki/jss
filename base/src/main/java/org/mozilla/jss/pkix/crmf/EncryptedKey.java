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
import org.mozilla.jss.asn1.CHOICE;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.asn1.Tag;

public class EncryptedKey implements ASN1Value {

    /**
     * The type of EncryptedKey.
     */
    public static class Type {
        private Type() { }

        static final Type ENCRYPTED_VALUE = new Type();
        static final Type ENVELOPED_DATA = new Type();
    }
    public static final Type ENCRYPTED_VALUE = Type.ENCRYPTED_VALUE;
    public static final Type ENVELOPED_DATA = Type.ENVELOPED_DATA;


    ///////////////////////////////////////////////////////////////////////
    // member and member access
    ///////////////////////////////////////////////////////////////////////
    private Type type;
    private EncryptedValue encryptedValue;
    private ANY envelopedData;

    public Type getType() {
        return type;
    }

    /**
     * Should only be called if <code>getType</code> returns
     * <code>ENCRYPTED_VALUE</code>.
     */
    public EncryptedValue getEncryptedValue() {
        return encryptedValue;
    }

    /**
     * Should only be called if <code>getType</code> returns
     * <code>ENVELOPED_DATA</code>. ANY is returned to prevent a circular
     * dependency between the org.mozilla.jss.pkcs7 package and the
     * org.mozilla.jss.pkix hierarchy.
     */
    public ANY getEnvelopedData() {
        return envelopedData;
    }

    ///////////////////////////////////////////////////////////////////////
    // Constructors
    ///////////////////////////////////////////////////////////////////////

    public EncryptedKey(EncryptedValue encryptedValue) {
        this.type = ENCRYPTED_VALUE;
        this.encryptedValue = encryptedValue;
        this.tag = SEQUENCE.TAG;
    }

    public EncryptedKey(ANY envelopedData) {
        this.type = ENVELOPED_DATA;
        this.envelopedData = envelopedData;
        this.tag = new Tag(0);
    }

    ///////////////////////////////////////////////////////////////////////
    // encoding/decoding
    ///////////////////////////////////////////////////////////////////////

    private Tag tag; // set by constructor based on type
    @Override
    public Tag getTag() {
        return tag;
    }

    @Override
    public void encode(OutputStream ostream) throws IOException {
        encode(getTag(), ostream);
    }

    @Override
    public void encode(Tag implicitTag, OutputStream ostream)
            throws IOException {

        // no IMPLICIT tags allowed on ANY
        assert( getTag().equals(implicitTag));

        if( type == ENCRYPTED_VALUE ) {
            assert( encryptedValue != null );
            encryptedValue.encode(implicitTag, ostream);
        } else {
            assert(type == ENVELOPED_DATA);
            assert(envelopedData != null);
            envelopedData.encode(implicitTag, ostream);
        }
    }

    private static final Template templateInstance = new Template();
    public static Template getTemplate() {
        return templateInstance;
    }

    /**
     * A Template for decoding BER-encoded EncryptedKeys.
     */
    public static class Template implements ASN1Template {

        private CHOICE.Template choicet;

        public Template() {
            choicet = new CHOICE.Template();

            choicet.addElement( EncryptedValue.getTemplate() );
            choicet.addElement( new Tag(0), ANY.getTemplate() );
        }

        @Override
        public boolean tagMatch(Tag tag) {
            return choicet.tagMatch(tag);
        }

        @Override
        public ASN1Value decode(InputStream istream)
                throws InvalidBERException, IOException {
          try {

            CHOICE choice = (CHOICE) choicet.decode(istream);

            if( choice.getTag().equals(SEQUENCE.TAG) ) {
                return new EncryptedKey( (EncryptedValue) choice.getValue() );
            } else {
                assert( choice.getTag().equals(new Tag(0)) );
                return new EncryptedKey( (ANY) choice.getValue() );
            }

          } catch(InvalidBERException e) {
                throw new InvalidBERException(e, "EncryptedKey");
          }
        }

        /**
         * @param implicitTag This parameter is ignored, because a CHOICE
         *      cannot have an implicitTag.
         */
        @Override
        public ASN1Value decode(Tag implicitTag, InputStream istream)
                throws InvalidBERException, IOException {
            throw new RuntimeException("EncryptedKey, being a CHOICE, cannot be"+
                " implicitly tagged");
            // return decode(istream);
        }
    }
}
