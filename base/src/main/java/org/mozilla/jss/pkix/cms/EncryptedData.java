/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkix.cms;

import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.pkcs7.EncryptedContentInfo;

/**
 * The PKCS #7 structure <i>EncryptedData</i>.
 */
public class EncryptedData extends org.mozilla.jss.pkcs7.EncryptedData {

    public EncryptedData(EncryptedContentInfo encryptedContentInfo) {
        super(encryptedContentInfo);
    }

    public EncryptedData(INTEGER version, EncryptedContentInfo encryptedContentInfo) {
        super(version, encryptedContentInfo);
    }

}
