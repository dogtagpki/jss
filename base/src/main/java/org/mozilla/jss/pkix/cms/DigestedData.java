/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkix.cms;

import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.asn1.OCTET_STRING;
import org.mozilla.jss.pkcs7.ContentInfo;
import org.mozilla.jss.pkix.primitive.AlgorithmIdentifier;

public class DigestedData extends org.mozilla.jss.pkcs7.DigestedData {

    public DigestedData(INTEGER version, AlgorithmIdentifier digestAlgorithm, ContentInfo contentInfo,
            OCTET_STRING digest) {
        super(version, digestAlgorithm, contentInfo, digest);
    }

}
