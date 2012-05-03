/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss.asn1;

import java.io.OutputStream;
import java.io.IOException;

/**
 * A value that can be decoded from BER and encoded to DER.
 *
 * @see ASN1Template
 */
public interface ASN1Value {

    /**
     * Returns the base tag for this type, not counting any tags
     * that may be imposed on it by its context.
     */
    public Tag getTag();

	/**
	 * Write this value's DER encoding to an output stream using
	 *	its own base tag.
	 */
    public void encode(OutputStream ostream) throws IOException;

	/**
	 * Write this value's DER encoding to an output stream using
	 * an implicit tag.
	 */
    public void encode(Tag implicitTag, OutputStream ostream)
        throws IOException;
}
