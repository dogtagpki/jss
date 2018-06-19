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
 * Represent the Qualifier.
 *
 * Qualifier ::= CHOICE {
 * cPRuri CPSuri,
 * userNotice UserNotice
 * }
 *
 * @author Thomas Kwan
 */
public class Qualifier implements java.io.Serializable {

    /**
     *
     */
    private static final long serialVersionUID = 2214531407387992974L;

    /**
     * Create a PolicyQualifierInfo
     *
     * @param id the ObjectIdentifier for the policy id.
     */
    public Qualifier() {
    }

    public Qualifier(DerValue val) throws IOException {
        // needs to override this
    }

    /**
     * Write the PolicyQualifier to the DerOutputStream.
     *
     * @param out the DerOutputStream to write the object to.
     * @exception IOException on errors.
     */
    public void encode(DerOutputStream out) throws IOException {
        // needs to override this
    }
}
