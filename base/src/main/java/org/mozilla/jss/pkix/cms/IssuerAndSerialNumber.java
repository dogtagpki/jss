/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkix.cms;

import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.pkix.primitive.Name;

/**
 * An issuer name and serial number, used to uniquely identify a certificate.
 */
public class IssuerAndSerialNumber extends org.mozilla.jss.pkcs7.IssuerAndSerialNumber {

    public IssuerAndSerialNumber(Name issuer, INTEGER serialNumber) {
        super(issuer, serialNumber);
    }

}
