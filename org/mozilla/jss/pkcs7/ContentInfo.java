/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkcs7;

import java.io.*;
import org.mozilla.jss.asn1.*;
import java.util.Vector;
import org.mozilla.jss.util.Assert;
import java.math.BigInteger;
import java.io.ByteArrayInputStream;

/**
 * A PKCS #7 ContentInfo structure.
 */
public class ContentInfo implements ASN1Value {

    public static final Tag TAG = SEQUENCE.TAG; // XXX is this right?


    public static OBJECT_IDENTIFIER DATA =
          new OBJECT_IDENTIFIER(new long[] { 1, 2, 840, 113549, 1, 7, 1  });
    public static OBJECT_IDENTIFIER SIGNED_DATA =
          new OBJECT_IDENTIFIER(new long[] { 1, 2, 840, 113549, 1, 7, 2  });
    public static OBJECT_IDENTIFIER ENVELOPED_DATA =
          new OBJECT_IDENTIFIER(new long[] { 1, 2, 840, 113549, 1, 7, 3  });
    public static OBJECT_IDENTIFIER SIGNED_AND_ENVELOPED_DATA =
          new OBJECT_IDENTIFIER(new long[] { 1, 2, 840, 113549, 1, 7, 4  });
    public static OBJECT_IDENTIFIER DIGESTED_DATA =
          new OBJECT_IDENTIFIER(new long[] { 1, 2, 840, 113549, 1, 7, 5  });
    public static OBJECT_IDENTIFIER ENCRYPTED_DATA =
          new OBJECT_IDENTIFIER(new long[] { 1, 2, 840, 113549, 1, 7, 6  });





    private OBJECT_IDENTIFIER contentType;
    private ANY content;
    private SEQUENCE sequence = new SEQUENCE();

    private ContentInfo() {}

    /**
     * Creates a ContentInfo with the given type and content.
     *
     * @param contentType The contentType of the ContentInfo.
     * @param content The content of the ContentInfo. May be <code>null</code>
     *      to signify that the optional content field is not present.
     */
    public ContentInfo(OBJECT_IDENTIFIER contentType, ASN1Value content) {
        this.contentType = contentType;
        sequence.addElement(contentType);
        if (content != null) {
            if( content instanceof ANY ) {
                this.content = (ANY) content;
            } else {
                // convert content to ANY
              try {
                this.content = (ANY) ASN1Util.decode(ANY.getTemplate(),
                                    ASN1Util.encode(content) );
              } catch(InvalidBERException e) {
                Assert.notReached("InvalidBERException while converting"+
                    "ASN1Value to ANY");
              }
            }
            sequence.addElement(new EXPLICIT(new Tag(0),content) );
        }
    }

    /**
     * Creates a ContentInfo of type <code>data</code>.
     */
    public ContentInfo(byte[] data) {
        this( DATA, new OCTET_STRING(data) );
    }

    /**
     * Creates a ContentInfo of type <code>signedData</code>.
     */
    public ContentInfo(SignedData sd) {
        this( SIGNED_DATA, sd);
    }

    /**
     * Creates a ContentInfo of type <code>envelopedData</code>.
     */
    public ContentInfo(EnvelopedData ed) {
        this( ENVELOPED_DATA, ed );
    }

    /**
     * Creates a ContentInfo of type <code>signedAndEnvelopedData</code>.
     */
    public ContentInfo(SignedAndEnvelopedData sed) {
        this( SIGNED_AND_ENVELOPED_DATA, sed );
    }

    /**
     * Creates a ContentInfo of type <code>digestedData</code>.
     */
    public ContentInfo(DigestedData dd) {
        this( DIGESTED_DATA, dd );
    }

    /**
     * Creates a ContentInfo of type <code>encryptedData</code>.
     */
    public ContentInfo(EncryptedData ed) {
        this( ENCRYPTED_DATA, ed );
    }

    /**
     * Returns the contentType field, which determines what kind of content
     * is contained in this ContentInfo.  It will usually be one of the six
     * predefined types, but may also be a user-defined type.
     */
    public OBJECT_IDENTIFIER getContentType() {
        return contentType;
    }

    /**
     * Returns <code>true</code> if the content field is present.
     */
    public boolean hasContent() {
        return (content != null);
    }

    /**
     * Returns the content, interpreted based on its type. If there is no
     * content, <code>null</code> is returned.
     * <p>If the contentType is
     *  one of the six standard types, the returned object will be of that
     *  type. For example, if the ContentInfo has contentType signedData,
     *  a SignedData object will be returned. If the contentType is data,
     *  an OCTET_STRING will be returned.
     * <p>If the contentType is <b>not</b> one of the six standard types,
     *      the returned object will be an ANY.
     */
    public ASN1Value getInterpretedContent() throws InvalidBERException {
        if(contentType.equals(DATA)) {
            return content.decodeWith( new OCTET_STRING.Template() );
        } else if( contentType.equals(SIGNED_DATA) ) {
            return content.decodeWith( new SignedData.Template() );
        } else if( contentType.equals(ENVELOPED_DATA) ) {
            return content.decodeWith( new EnvelopedData.Template());
        } else if( contentType.equals(SIGNED_AND_ENVELOPED_DATA) ) {
            return content.decodeWith(
                        new SignedAndEnvelopedData.Template() );
        } else if( contentType.equals(DIGESTED_DATA) ) {
            return content.decodeWith( new DigestedData.Template() );
        } else if( contentType.equals(ENCRYPTED_DATA) ) {
            return content.decodeWith( new EncryptedData.Template());
        } else {
            // unknown type
            return content;
        }
    }

    /**
     * Returns the content encoded as an ANY. If there is no content,
     * <code>null</code> is returned.
     */
    public ANY getContent() {
        return content;
    }

    public void encode(OutputStream ostream) throws IOException {
        encode(getTag(),ostream);
    }

    public void encode(Tag implicitTag, OutputStream ostream)
        throws IOException
    {
        sequence.encode(implicitTag,ostream);
    }

    public Tag getTag() {
        return ContentInfo.TAG;
    }

    /**
     * Returns a singleton instance of a decoding template for ContentInfo.
     */
    public static Template getTemplate() {
        return templateInstance;
    }
    private static Template templateInstance = new Template();

    /**
     * A template for decoding a ContentInfo blob
     *
     */
    public static class Template implements ASN1Template {
        public boolean tagMatch(Tag tag) {
            return (tag.equals(ContentInfo.TAG));
        }

        private SEQUENCE.Template seqt;

        public Template() {
            seqt = new SEQUENCE.Template();
            seqt.addElement(new OBJECT_IDENTIFIER.Template());
            seqt.addOptionalElement(
               new EXPLICIT.Template(
                         new Tag(0), new ANY.Template()
                        ));
        }

        public ASN1Value decode(InputStream istream)
            throws IOException, InvalidBERException
            {
                return decode(ContentInfo.TAG,istream);
            }


        public ASN1Value decode(Tag implicitTag, InputStream istream )
            throws IOException, InvalidBERException
            {
                SEQUENCE seq = (SEQUENCE) seqt.decode(implicitTag,istream);
                Assert._assert(seq.size() == 2);
                ASN1Value content;

                if( seq.elementAt(1) == null ) {
                    content = null;
                } else {
                    content = ((EXPLICIT)seq.elementAt(1)).getContent();
                }

                return new ContentInfo(
                    (OBJECT_IDENTIFIER) seq.elementAt(0),
                    content
                    );
            }
    } // end of template

}
