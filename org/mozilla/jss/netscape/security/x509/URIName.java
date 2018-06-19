// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package org.mozilla.jss.netscape.security.x509;

import java.io.IOException;

import org.mozilla.jss.netscape.security.util.DerOutputStream;
import org.mozilla.jss.netscape.security.util.DerValue;

/**
 * This class implements the URIName as required by the GeneralNames
 * ASN.1 object.
 *
 * @author Amit Kapoor
 * @author Hemma Prafullchandra
 * @version 1.3
 * @see GeneralName
 * @see GeneralNames
 * @see GeneralNameInterface
 */
public class URIName implements GeneralNameInterface {
    /**
     *
     */
    private static final long serialVersionUID = 8340049830612859508L;
    private String name;

    /**
     * Create the URIName object from the passed encoded Der value.
     *
     * @param derValue the encoded DER URIName.
     * @exception IOException on error.
     */
    public URIName(DerValue derValue) throws IOException {
        name = derValue.getIA5String();
    }

    /**
     * Create the URIName object with the specified name.
     *
     * @param name the URIName.
     */
    public URIName(String name) {
        this.name = name;
    }

    /**
     * Return the type of the GeneralName.
     */
    public int getType() {
        return (GeneralNameInterface.NAME_URI);
    }

    /**
     * Encode the URI name into the DerOutputStream.
     *
     * @param out the DER stream to encode the URIName to.
     * @exception IOException on encoding errors.
     */
    public void encode(DerOutputStream out) throws IOException {
        out.putIA5String(name);
    }

    /**
     * Convert the name into user readable string.
     */
    public String toString() {
        return ("URIName: " + name);
    }
}
