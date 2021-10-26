/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkcs11;

/**
 * A certificate that lives on the internal token.  It has database information
 * (like trust flags) but also PKCS #11 information (like unique ID).
 *
 * @deprecated Use PK11Cert instead.
 */
@Deprecated
public final class PK11InternalTokenCert extends PK11InternalCert {

    PK11InternalTokenCert(byte[] certPtr, byte[] slotPtr, String nickname) {
        super(certPtr, slotPtr, nickname);
    }
}
