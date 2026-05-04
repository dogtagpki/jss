/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkix.primitive;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.mozilla.jss.asn1.ASN1Template;
import org.mozilla.jss.asn1.ASN1Value;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.asn1.Tag;

/**
 * PKCS #5 <i>PBMAC1-params</i> from RFC 9879.
 *
 * <pre>
 * PBMAC1-params ::= SEQUENCE {
 *   keyDerivationFunc AlgorithmIdentifier {{PBMAC1-KDFs}},
 *   messageAuthScheme AlgorithmIdentifier {{PBMAC1-MACs}}
 * }
 * </pre>
 */
public class PBMAC1Params implements ASN1Value {

    ///////////////////////////////////////////////////////////////////////
    // members and member access
    ///////////////////////////////////////////////////////////////////////
    private AlgorithmIdentifier keyDerivationFunc;
    private AlgorithmIdentifier messageAuthScheme;
    private SEQUENCE sequence;

    /**
     * Returns the key derivation function (typically PBKDF2).
     */
    public AlgorithmIdentifier getKeyDerivationFunc() {
        return keyDerivationFunc;
    }

    /**
     * Returns the message authentication scheme (typically HMAC-SHA256/384/512).
     */
    public AlgorithmIdentifier getMessageAuthScheme() {
        return messageAuthScheme;
    }

    ///////////////////////////////////////////////////////////////////////
    // constructors
    ///////////////////////////////////////////////////////////////////////

    /**
     * Creates PBMAC1 parameters.
     *
     * @param keyDerivationFunc The key derivation function AlgorithmIdentifier
     *                          (typically PBKDF2 with salt, iterations, and PRF)
     * @param messageAuthScheme The MAC algorithm AlgorithmIdentifier
     *                          (typically HMAC-SHA256, HMAC-SHA384, or HMAC-SHA512)
     */
    public PBMAC1Params(AlgorithmIdentifier keyDerivationFunc,
                        AlgorithmIdentifier messageAuthScheme) {

        if (keyDerivationFunc == null || messageAuthScheme == null) {
            throw new IllegalArgumentException("Parameters cannot be null");
        }

        this.keyDerivationFunc = keyDerivationFunc;
        this.messageAuthScheme = messageAuthScheme;
        sequence = new SEQUENCE();
        sequence.addElement(keyDerivationFunc);
        sequence.addElement(messageAuthScheme);
    }

    ///////////////////////////////////////////////////////////////////////
    // DER encoding
    ///////////////////////////////////////////////////////////////////////

    private static final Tag TAG = SEQUENCE.TAG;

    /**
    * Returns the ASN.1 tag for this structure.
    *
    * @return The SEQUENCE tag
    */
    @Override
    public Tag getTag() {
        return TAG;
    }

    /**
    * Encodes this PBMAC1Params to the output stream.
    *
    * @param ostream The output stream
    * @throws IOException if encoding fails
    */
    @Override
    public void encode(OutputStream ostream) throws IOException {
        sequence.encode(ostream);
    }

    /**
    * Encodes this PBMAC1Params with an implicit tag.
    *
    * @param implicitTag The implicit tag to use
    * @param ostream The output stream
    * @throws IOException if encoding fails
    */
    @Override
    public void encode(Tag implicitTag, OutputStream ostream)
        throws IOException
    {
        sequence.encode(implicitTag, ostream);
    }

    private static final Template templateInstance = new Template();

    /**
    * Returns the template for decoding PBMAC1Params.
    *
    * @return The PBMAC1Params template
    */
    public static Template getTemplate() {
        return templateInstance;
    }

    /**
     * A template class for decoding PBMAC1Params.
     */
    public static class Template implements ASN1Template {

        private SEQUENCE.Template seqt;

        /**
        * Creates a new PBMAC1Params template.
        */
        public Template() {
            seqt = new SEQUENCE.Template();
            seqt.addElement(AlgorithmIdentifier.getTemplate());
            seqt.addElement(AlgorithmIdentifier.getTemplate());
        }

        /**
        * Returns whether the given tag matches this template.
        *
        * @param tag The tag to check
        * @return true if the tag matches
        */
        @Override
        public boolean tagMatch(Tag tag) {
            return TAG.equals(tag);
        }

        /**
        * Decodes a PBMAC1Params from the input stream.
        *
        * @param istream The input stream
        * @return The decoded PBMAC1Params
        * @throws InvalidBERException if decoding fails
        * @throws IOException if an I/O error occurs
        */
        @Override
        public ASN1Value decode(InputStream istream)
            throws InvalidBERException, IOException
        {
            return decode(TAG, istream);
        }

        /**
        * Decodes a PBMAC1Params with an implicit tag.
        *
        * @param implicitTag The implicit tag
        * @param istream The input stream
        * @return The decoded PBMAC1Params
        * @throws InvalidBERException if decoding fails
        * @throws IOException if an I/O error occurs
        */
        @Override
        public ASN1Value decode(Tag implicitTag, InputStream istream)
            throws InvalidBERException, IOException
        {
            SEQUENCE seq = (SEQUENCE) seqt.decode(implicitTag, istream);

            return new PBMAC1Params((AlgorithmIdentifier) seq.elementAt(0),
                                    (AlgorithmIdentifier) seq.elementAt(1));
        }
    }
}
