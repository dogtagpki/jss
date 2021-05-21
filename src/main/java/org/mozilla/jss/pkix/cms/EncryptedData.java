/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkix.cms;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.mozilla.jss.asn1.ASN1Template;
import org.mozilla.jss.asn1.ASN1Value;
import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.asn1.Tag;

/**
 * The PKCS #7 structure <i>EncryptedData</i>.
 */
public class EncryptedData implements ASN1Value {

    ///////////////////////////////////////////////////////////////////////
    // Members
    ///////////////////////////////////////////////////////////////////////
    private INTEGER version;
    private EncryptedContentInfo encryptedContentInfo;
    private SEQUENCE sequence;

    /**
     * The default version number.  This should always be used unless
     * you really know what you are doing.
     */
    public static final INTEGER DEFAULT_VERSION = new INTEGER(0);

    ///////////////////////////////////////////////////////////////////////
    // Constructors
    ///////////////////////////////////////////////////////////////////////

    /**
     * Creates a new EncryptedData.
     *
     * @param version Should usually be DEFAULT_VERSION unless you are being
     *      very clever.
     */
    public EncryptedData(   INTEGER version,
                            EncryptedContentInfo encryptedContentInfo )
    {
        if( version == null || encryptedContentInfo == null ) {
            throw new IllegalArgumentException("null parameter");
        }

        sequence = new SEQUENCE();

        this.version = version;
        sequence.addElement(version);
        this.encryptedContentInfo = encryptedContentInfo;
        sequence.addElement(encryptedContentInfo);
    }

    /**
     * Creates an EncryptedData with the default version.
     */
    public EncryptedData( EncryptedContentInfo encryptedContentInfo ) {
        this( DEFAULT_VERSION, encryptedContentInfo );
    }

    ///////////////////////////////////////////////////////////////////////
    // Accessor Methods
    ///////////////////////////////////////////////////////////////////////
    public INTEGER getVersion() {
        return version;
    }

    public EncryptedContentInfo getEncryptedContentInfo() {
        return encryptedContentInfo;
    }


    ///////////////////////////////////////////////////////////////////////
    //  DER encoding
    ///////////////////////////////////////////////////////////////////////

    private static final Tag TAG = SEQUENCE.TAG;
    @Override
    public Tag getTag() {
        return TAG;
    }

    @Override
    public void encode(OutputStream ostream) throws IOException {
        sequence.encode(ostream);
    }

    @Override
    public void encode(Tag implicitTag, OutputStream ostream)
        throws IOException
    {
        sequence.encode(implicitTag, ostream);
    }

    public static Template getTemplate() {
        return templateInstance;
    }
    private static final Template templateInstance = new Template();

    /**
     * A Template for decoding EncryptedData items.
     */
    public static class Template implements ASN1Template {

        private SEQUENCE.Template seqt;

        public Template() {
            seqt = new SEQUENCE.Template();
            seqt.addElement( INTEGER.getTemplate() );
            seqt.addElement( EncryptedContentInfo.getTemplate() );
        }

        @Override
        public boolean tagMatch(Tag tag) {
            return TAG.equals(tag);
        }

        @Override
        public ASN1Value decode(InputStream istream)
            throws InvalidBERException, IOException
        {
            return decode(TAG, istream);
        }

        @Override
        public ASN1Value decode(Tag implicitTag, InputStream istream)
            throws InvalidBERException, IOException
        {

            SEQUENCE seq = (SEQUENCE) seqt.decode(implicitTag, istream);

            return new EncryptedData(
                        (INTEGER)               seq.elementAt(0),
                        (EncryptedContentInfo)  seq.elementAt(1) );
        }
    }
}
