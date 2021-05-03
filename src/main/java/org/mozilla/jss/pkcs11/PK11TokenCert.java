/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkcs11;

import org.mozilla.jss.crypto.*;

/**
 * A user certificate that lives on a PKCS #11 token.
 */
public final class PK11TokenCert extends PK11Cert implements TokenCertificate
{
    public byte[] getUniqueID() {
        return super.getUniqueID();
    }

    public CryptoToken getOwningToken() {
        return super.getOwningToken();
    }

    PK11TokenCert(byte[] certPtr, byte[] slotPtr, String nickname) {
        super(certPtr, slotPtr, nickname);
    }
}
