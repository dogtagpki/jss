/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkix.crmf;

import org.mozilla.jss.asn1.*;
import java.io.*;
import org.mozilla.jss.pkix.primitive.*;

/**
 * The CRMF structure <i>EncryptedValue</i> for storing the encrypted
 * key to be archived.
 */
public class EncryptedValue implements ASN1Value {

    ///////////////////////////////////////////////////////////////////////
    // members and member access
    ///////////////////////////////////////////////////////////////////////
    private AlgorithmIdentifier intendedAlg; // may be null
    private AlgorithmIdentifier symmAlg; // may be null
    private BIT_STRING encSymmKey; // may be null
    private AlgorithmIdentifier keyAlg; // may be null
    private OCTET_STRING valueHint; // may be null
    private BIT_STRING encValue; // may be null
    private SEQUENCE sequence;

    /**
     * May return <code>null</code>.
     */
    public AlgorithmIdentifier getIntendedAlg() {
        return intendedAlg;
    }

    /**
     * May return <code>null</code>.
     */
    public AlgorithmIdentifier getSymmAlg() {
        return symmAlg;
    }

    /**
     * May return <code>null</code>.
     */
    public BIT_STRING getEncSymmKey() {
        return encSymmKey;
    }

    /**
     * May return <code>null</code>.
     */
    public AlgorithmIdentifier getKeyAlg() {
        return keyAlg;
    }

    /**
     * May return <code>null</code>.
     */
    public OCTET_STRING getValueHint() {
        return valueHint;
    }

    public BIT_STRING getEncValue() {
        return encValue;
    }

    ///////////////////////////////////////////////////////////////////////
    // Constructors
    ///////////////////////////////////////////////////////////////////////

    private EncryptedValue() { }

    /**
     * @param intendedAlg May be null.
     * @param symmAlg May be null.
     * @param encSymmKey May be null.
     * @param keyAlg May be null.
     * @param valueHint May be null.
     * @param encValue May <b>not</b> be null.
     */
    public EncryptedValue(  AlgorithmIdentifier intendedAlg,
                            AlgorithmIdentifier symmAlg,
                            BIT_STRING encSymmKey,
                            AlgorithmIdentifier keyAlg,
                            OCTET_STRING valueHint,
                            BIT_STRING encValue ) {
        if( encValue == null ) {
            throw new IllegalArgumentException("encValue is null");
        }

        this.intendedAlg = intendedAlg;
        this.symmAlg = symmAlg;
        this.encSymmKey = encSymmKey;
        this.keyAlg = keyAlg;
        this.valueHint = valueHint;
        this.encValue = encValue;

        sequence = new SEQUENCE();
        if(intendedAlg!=null) {
            sequence.addElement( new Tag(0), intendedAlg );
        }
        if( symmAlg!=null ) {
            sequence.addElement( new Tag(1), symmAlg );
        }
        if( encSymmKey!=null ) {
            sequence.addElement( new Tag(2), encSymmKey );
        }
        if( keyAlg!=null ) {
            sequence.addElement( new Tag(3), keyAlg );
        }
        if( valueHint!=null ) {
            sequence.addElement( new Tag(4), valueHint );
        }
        sequence.addElement(encValue);
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
     * A Template class for decoding BER-encoded EncryptedValues. 
     */
    public static class Template implements ASN1Template {

        private SEQUENCE.Template seqt;

        public Template()  {
            seqt = new SEQUENCE.Template();

            seqt.addOptionalElement( new Tag(0),
                        AlgorithmIdentifier.getTemplate());
            seqt.addOptionalElement( new Tag(1),
                        AlgorithmIdentifier.getTemplate());
            seqt.addOptionalElement( new Tag(2),
                        BIT_STRING.getTemplate());
            seqt.addOptionalElement( new Tag(3),
                        AlgorithmIdentifier.getTemplate());
            seqt.addOptionalElement( new Tag(4),
                        OCTET_STRING.getTemplate());
            seqt.addElement( BIT_STRING.getTemplate() );
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
          try {

            SEQUENCE seq = (SEQUENCE) seqt.decode(implicitTag, istream);

            return new EncryptedValue(
                            (AlgorithmIdentifier) seq.elementAt(0),
                            (AlgorithmIdentifier) seq.elementAt(1),
                            (BIT_STRING) seq.elementAt(2),
                            (AlgorithmIdentifier) seq.elementAt(3),
                            (OCTET_STRING) seq.elementAt(4),
                            (BIT_STRING) seq.elementAt(5) );

          } catch(InvalidBERException e ) {
            throw new InvalidBERException(e, "EncryptedValue");
          }
        }
    }
}
