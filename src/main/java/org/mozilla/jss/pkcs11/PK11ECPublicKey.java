/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkcs11;

import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.ECParameterSpec;
import java.math.BigInteger;

import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.util.EC;

public final class PK11ECPublicKey extends PK11PubKey implements ECPublicKey {

    private static final long serialVersionUID = 1L;
    public PK11ECPublicKey(byte[] pointer) {
        super(pointer);
    }

    public ECParameterSpec getParams() {
        byte[] curveData = getCurveByteArray();
        return EC.decodeNSSOID(curveData);
    }

    public byte[] getCurveBA() {
        return getCurveByteArray();
    }

    public ECPoint getW() {
        byte[] pointData = getWByteArray();
        return EC.decodeNSSPoint(pointData);
    }

    private native byte[] getCurveByteArray();
    public native byte[] getWByteArray();
}
