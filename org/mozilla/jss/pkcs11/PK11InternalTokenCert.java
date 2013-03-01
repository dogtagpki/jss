/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkcs11;

import org.mozilla.jss.crypto.*;

/**
 * A certificate that lives on the internal token.  It has database information
 * (like trust flags) but also PKCS #11 information (like unique ID).
 */
public final class PK11InternalTokenCert extends PK11InternalCert
    implements TokenCertificate
{
    public byte[] getUniqueID() {
        return super.getUniqueID();
    }

    public CryptoToken getOwningToken() {
        return super.getOwningToken();
    }

    PK11InternalTokenCert(byte[] certPtr, byte[] slotPtr, String nickname) {
        super(certPtr, slotPtr, nickname);
    }
}
