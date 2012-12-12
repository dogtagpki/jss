/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss.asn1;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.ByteArrayOutputStream;
import org.mozilla.jss.util.Assert;

/**
 * An explicit tag.
 */
public class EXPLICIT implements ASN1Value {

    public static final Form FORM = Form.CONSTRUCTED;

    private ASN1Value content;
    private Tag tag;

    private EXPLICIT() { }

    /**
     * Creates an EXPLICIT tag wrapping some other ASN1Value.  For example,
     * for the following ASN.1 snippet:
     * <pre>
     * MyType [3] EXPLICIT INTEGER
     * </pre>
     * assuming a sample value of 5 for the INTEGER, a MyType could be
     * created with:
     * <pre>
     *  EXPLICIT myValue = new EXPLICIT( new Tag(3), new INTEGER(5) );
     * </pre>
     */
    public EXPLICIT( Tag tag, ASN1Value content ) {
        Assert._assert(tag!=null && content!=null);
        this.content = content;
        this.tag = tag;
    }

    /**
     * Returns the ASN1Value that is wrapped by this EXPLICIT tag.
     */
    public ASN1Value getContent() {
        return content;
    }

    /**
     * Returns the Tag of this EXPLICIT tag.
     */
    public Tag getTag() {
        return tag;
    }

    public void encode(OutputStream ostream) throws IOException {
        encode(tag, ostream);
    }

    public void encode(Tag implicitTag, OutputStream ostream)
        throws IOException
    {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        content.encode(bos);
        byte[] contentBytes = bos.toByteArray();
        ASN1Header head = new ASN1Header(implicitTag, FORM,
            contentBytes.length );
        head.encode(ostream);
        ostream.write(contentBytes);
    }

    public static Template getTemplate( Tag tag, ASN1Template content) {
        return new Template(tag, content);
    }

/**
 * A template for decoding an object wrapped in an EXPLICIT tag.
 */
public static class Template implements ASN1Template {

    private ASN1Template content;
    private Tag tag;

    private Template() { }

    /**
     * Creates a template for unwrapping an object wrapped in an explicit tag.
     * For example, to decode:
     * <pre>
     * MyValue ::= [3] EXPLICIT INTEGER
     * </pre>
     * use:
     * <pre>
     * EXPLICIT.Template myTemplate = new EXPLICIT.Template( new Tag(3),
     *      new INTEGER.Template() );
     * </pre>
     *
     * @param tag The tag value of the EXPLICIT tag.
     * @param content The template for decoding the object that is wrapped
     *      in the explicit tag.
     */
    public Template(Tag tag, ASN1Template content) {
        this.content = content;
        this.tag = tag;
    }

    public boolean tagMatch(Tag tag) {
        return( this.tag.equals(tag) );
    }

    public ASN1Value decode(InputStream istream)
        throws IOException, InvalidBERException
    {
        return decode(tag, istream);
    }

    public ASN1Value decode(Tag implicitTag, InputStream istream)
        throws IOException, InvalidBERException
    {
      try {
        ASN1Header head = new ASN1Header(istream);

        head.validate( implicitTag, FORM.CONSTRUCTED );

        ASN1Value val = content.decode(istream);

        EXPLICIT e = new EXPLICIT(tag, val);

        // if indefinite content length, consume the end-of-content marker
        if( head.getContentLength() == -1 ) {
            head = new ASN1Header(istream);

            if( ! head.isEOC() ) {
                throw new InvalidBERException("No end-of-contents marker");
            }
        }

        return e;

      } catch(InvalidBERException e) {
        throw new InvalidBERException(e, "EXPLICIT");
      }
    }
} // end of Template

}
