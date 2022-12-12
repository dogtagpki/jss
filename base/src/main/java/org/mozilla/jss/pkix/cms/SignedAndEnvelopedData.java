/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkix.cms;

import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.asn1.SET;
import org.mozilla.jss.pkcs7.EncryptedContentInfo;

public class SignedAndEnvelopedData extends org.mozilla.jss.pkcs7.SignedAndEnvelopedData {

    public SignedAndEnvelopedData(INTEGER version, SET recipientInfos, SET digestAlgorithms,
            EncryptedContentInfo encryptedContentInfo, SET certificates, SET crls, SET signerInfos) {
        super(version, recipientInfos, digestAlgorithms, encryptedContentInfo, certificates, crls, signerInfos);
    }
}
