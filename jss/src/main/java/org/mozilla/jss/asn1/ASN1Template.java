/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss.asn1;

import java.io.IOException;
import java.io.InputStream;

/**
 * An interface for decoding ASN1Values from their BER encodings.
 *
 * @see ASN1Value
 */
public interface ASN1Template {

    /**
     * Determines whether the given tag will satisfy this template.
     *
     * @param tag Tag.
     * @return True if the given tag will satisfy this template.
     */
    public boolean tagMatch(Tag tag);

    /**
     * Decodes an ASN1Value from the InputStream without an implicit tag.
     * @param istream Must support marking (markSupported() == true).
     *      For example, ByteArrayInputStream and BufferedInputStream
     *      support marking, but FileInputStream does not. If your source
     *      does not support marking, you can wrap it in a
     *      BufferedInputStream.
     * @return ASN.1 value.
     * @throws InvalidBERException If there is an invalid BER encoding.
     * @throws IOException If other error occurred.
     */
    public ASN1Value decode(InputStream istream)
        throws IOException, InvalidBERException;

    /**
     * Decodes an ASN1Value from the InputStream with the given implicit
     *      tag.
     * @param implicitTag Implicit tag.
     * @param istream Must support marking (markSupported() == true).
     *      For example, ByteArrayInputStream and BufferedInputStream
     *      support marking, but FileInputStream does not. If your source
     *      does not support marking, you can wrap it in a
     *      BufferedInputStream.
     * @return ASN.1 value.
     * @throws InvalidBERException If there is an invalid BER encoding.
     * @throws IOException If other error occurred.
     */
    public ASN1Value decode(Tag implicitTag, InputStream istream)
        throws IOException, InvalidBERException;
}
