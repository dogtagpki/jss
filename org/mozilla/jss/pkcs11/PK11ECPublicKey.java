/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkcs11;

// Requires JAVA 1.5
//import java.security.interfaces.ECPublicKey;
import java.math.BigInteger;

//
// Requires JAVA 1.5
//public final class PK11ECPublicKey extends PK11PubKey implements ECPublicKey {
public final class PK11ECPublicKey extends PK11PubKey {

    private static final long serialVersionUID = 1L;
    public PK11ECPublicKey(byte[] pointer) {
        super(pointer);
    }

//
// Requires JAVA 1.5
//    public ECParams getCurve() {
//      try {
//        return new BigInteger( getCurveByteArray() );
//      } catch(NumberFormatException e) {
//          throw new RuntimeException("Unable to decode DSA parameters: " + e.getMessage(), e);
//      }
//    }
//

    public BigInteger getCurve() {
      try {
        return new BigInteger( getCurveByteArray() );
      } catch(NumberFormatException e) {
          throw new RuntimeException("Unable to decode EC curve: " + e.getMessage(), e);
      }
    }

    public byte[] getCurveBA() {
        return getCurveByteArray();
    }

    public BigInteger getW() {
      try {
        return new BigInteger( getWByteArray() );
      } catch(NumberFormatException e) {
          throw new RuntimeException("Unable to decode EC public value: " + e.getMessage(), e);
      }
    }

    private native byte[] getCurveByteArray();
    private native byte[] getWByteArray();
}
