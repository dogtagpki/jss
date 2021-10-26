/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkcs11;

/**
 * A certificate that lives in the internal cert database.
 *
 * @deprecated Use PK11Cert instead.
 */
@Deprecated
public class PK11InternalCert extends PK11Cert {

    PK11InternalCert(byte[] certPtr, byte[] slotPtr, String nickname) {
        super(certPtr, slotPtr, nickname);
    }
}
