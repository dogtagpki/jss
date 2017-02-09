/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkcs11;

import org.mozilla.jss.util.Assert;
// Requires JAVA 1.5
//import java.security.interfaces.ECPublicKey;
import java.math.BigInteger;

//
// Requires JAVA 1.5
//public final class PK11ECPublicKey extends PK11PubKey implements ECPublicKey {
public final class PK11ECPublicKey extends PK11PubKey {
    
    public PK11ECPublicKey(byte[] pointer) {
        super(pointer);
    }

//
// Requires JAVA 1.5
//    public ECParams getCurve() {
//      try {
//        return new BigInteger( getCurveByteArray() );
//      } catch(NumberFormatException e) {
//       Assert.notReached("Unable to decode DSA parameters");
//       return null;
//      }
//    }
//
//    public BigInteger getW() {
//      try {
//        return new BigInteger( getWByteArray() );
//      } catch(NumberFormatException e) {
//        Assert.notReached("Unable to decode DSA public value");
//        return null;
//      }
//    }
//
//    private native byte[] getCurveByteArray();
//    private native byte[] getWByteArray();
}
